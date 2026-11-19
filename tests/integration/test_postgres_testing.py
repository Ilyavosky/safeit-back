from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from psycopg_pool import AsyncConnectionPool

from app.application.ports.testing import ToolOutput
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.cve.lookup_cve import LookupCve
from app.application.use_cases.testing.run_scan_tests import RunScanTests
from app.domain.entities.cve import CveRecord
from app.domain.entities.finding import Finding
from app.domain.entities.raw_finding import RawFinding
from app.domain.entities.scan import Scan
from app.domain.entities.test_run import TestRun
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.scan_type import ScanType
from app.domain.value_objects.severity import Severity
from app.infrastructure.db.audit_repository import PostgresAuditRepository
from app.infrastructure.db.cve_repository import PostgresCveRepository
from app.infrastructure.db.domain_repository import PostgresDomainRepository
from app.infrastructure.db.endpoint_repository import PostgresEndpointRepository
from app.infrastructure.db.finding_repository import PostgresFindingRepository
from app.infrastructure.db.scan_repository import PostgresScanRepository
from app.infrastructure.db.test_run_repository import PostgresTestRunRepository
from app.infrastructure.db.tool_repository import PostgresToolRepository
from app.infrastructure.security.aes_gcm_cipher import AesGcmCipher
from app.infrastructure.testing.fixed_planner import FixedProbePlanner
from tests.fakes import FakeClock
from tests.fakes_cve import FakeEpss, FakeKev, FakeNvd
from tests.fakes_testing import FakeRegistry, FakeRunner
from tests.pg_seed import seed_world
from tests.unit.test_secret_cipher import KEY

LOG4J = "CVE-2021-44228"


async def test_repositories_roundtrip(migrated_pool: AsyncConnectionPool[Any]) -> None:
    world = await seed_world(migrated_pool)
    scans = PostgresScanRepository(migrated_pool)
    now = datetime.now(UTC)
    scan = Scan(uuid4(), world.domain.id, world.user.id, ScanType.TESTS, JobStatus.QUEUED, now)
    await scans.add(scan)
    assert await scans.get(scan.id) == scan
    assert await scans.get(uuid4()) is None
    running = scan.start(now)
    await scans.save(running)
    assert await scans.get(scan.id) == running

    endpoints = await PostgresEndpointRepository(migrated_pool).list_testable(world.domain.id)
    assert [(e.id, e.url, e.technologies, e.in_scope) for e in endpoints] == [
        (world.endpoint_id, "https://example.com/", ("nginx",), True)
    ]
    assert await PostgresEndpointRepository(migrated_pool).list_testable(uuid4()) == []

    tools = PostgresToolRepository(migrated_pool)
    nuclei = await tools.get_by_name("nuclei")
    assert nuclei is not None
    assert nuclei.allowed_params["rate_limit"] == 50
    assert await tools.get_by_name("sqlmap") is None

    runs = PostgresTestRunRepository(migrated_pool)
    run = TestRun(
        uuid4(),
        scan.id,
        world.endpoint_id,
        nuclei.id,
        "nuclei",
        {"tags": ["cve"]},
        JobStatus.QUEUED,
    )
    await runs.add(run)
    started = run.start(now)
    await runs.save(started, None)
    finished = started.finish(JobStatus.DONE, datetime.now(UTC))
    await runs.save(finished, b"v1:token")
    assert await runs.list_by_scan(scan.id) == [finished]
    async with migrated_pool.connection() as conn:
        cursor = await conn.execute(
            "select result_enc from public.test_runs where id = %s", (run.id,)
        )
        row = await cursor.fetchone()
    assert row is not None
    assert bytes(row[0]) == b"v1:token"

    await PostgresCveRepository(migrated_pool).upsert_changed(
        [CveRecord(LOG4J, 10.0, None, 0.9, True, now)]
    )
    findings = PostgresFindingRepository(migrated_pool)
    finding = Finding(
        uuid4(),
        run.id,
        world.endpoint_id,
        "Log4j",
        Severity.CRITICAL,
        100.0,
        RemediationStatus.OPEN,
        now,
        (LOG4J,),
    )
    await findings.add(finding, b"v1:evidence")
    assert await findings.list_by_scan(scan.id) == [finding]
    assert await findings.list_by_scan(uuid4()) == []


async def test_full_run_against_postgres(migrated_pool: AsyncConnectionPool[Any]) -> None:
    world = await seed_world(migrated_pool)
    clock = FakeClock()
    cves = PostgresCveRepository(migrated_pool)
    await cves.upsert_changed([CveRecord(LOG4J, 10.0, None, 0.94, True, clock.now())])
    runners = {name: FakeRunner() for name in ("headers", "testssl", "nuclei")}
    runners["nuclei"].output = ToolOutput(
        [RawFinding("Log4j", Severity.CRITICAL, "evidencia", (LOG4J, "CVE-2000-0001"))], "{}"
    )
    scans = PostgresScanRepository(migrated_pool)
    runs = PostgresTestRunRepository(migrated_pool)
    findings = PostgresFindingRepository(migrated_pool)
    use_case = RunScanTests(
        domains=PostgresDomainRepository(migrated_pool),
        scans=scans,
        endpoints=PostgresEndpointRepository(migrated_pool),
        tools=PostgresToolRepository(migrated_pool),
        test_runs=runs,
        findings=findings,
        cves=cves,
        lookup_cve=LookupCve(cves, FakeNvd(), FakeEpss(), FakeKev(), clock),
        registry=FakeRegistry(runners),
        planner=FixedProbePlanner(),
        cipher=AesGcmCipher(KEY),
        audit=RecordAction(PostgresAuditRepository(migrated_pool)),
        clock=clock,
    )
    scan = Scan(
        uuid4(), world.domain.id, world.user.id, ScanType.TESTS, JobStatus.QUEUED, clock.now()
    )
    await scans.add(scan)
    result = await use_case.execute(scan.id)
    assert result is not None
    assert result.status is JobStatus.DONE
    stored = await runs.list_by_scan(scan.id)
    assert sorted(r.tool_name for r in stored) == ["headers", "nuclei", "testssl"]
    listed = await findings.list_by_scan(scan.id)
    assert [(f.title, f.priority_score, f.cve_ids) for f in listed] == [("Log4j", 100.0, (LOG4J,))]
    async with migrated_pool.connection() as conn:
        cursor = await conn.execute(
            "select count(*) from public.test_runs where scan_id = %s and result_enc is not null",
            (scan.id,),
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] == 3
