from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from psycopg_pool import AsyncConnectionPool

from app.application.pagination import clamp_limit
from app.application.ports.findings_query import FindingFilter, FindingSort, Scope
from app.domain.entities.finding import Finding
from app.domain.entities.report import Recommendation, Report
from app.domain.entities.scan import Scan
from app.domain.entities.test_run import TestRun
from app.domain.errors import InvalidCursorError
from app.domain.value_objects.finding_lifecycle import FindingLifecycle
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.recommendation_status import RecommendationStatus
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.scan_type import ScanType
from app.domain.value_objects.severity import Severity
from app.infrastructure.db.finding_query_repository import PostgresFindingQueryRepository
from app.infrastructure.db.finding_repository import PostgresFindingRepository
from app.infrastructure.db.report_repository import PostgresReportRepository
from app.infrastructure.db.scan_repository import PostgresScanRepository
from app.infrastructure.db.test_run_repository import PostgresTestRunRepository
from tests.pg_seed import World, seed_world


async def _scan_with_findings(
    pool: AsyncConnectionPool[Any],
    world: World,
    specs: list[tuple[str, Severity, float | None]],
    *,
    status: JobStatus = JobStatus.DONE,
    created: datetime | None = None,
) -> tuple[Scan, list[Finding]]:
    now = created or datetime.now(UTC)
    scan = Scan(uuid4(), world.domain.id, world.user.id, ScanType.TESTS, JobStatus.QUEUED, now)
    await PostgresScanRepository(pool).add(scan)
    run = TestRun(
        uuid4(),
        scan.id,
        world.endpoint_id,
        world.tool_ids["headers"],
        "headers",
        {},
        JobStatus.QUEUED,
    )
    await PostgresTestRunRepository(pool).add(run)
    repo = PostgresFindingRepository(pool)
    findings = []
    for offset, (title, severity, score) in enumerate(specs):
        finding = Finding(
            uuid4(),
            run.id,
            world.endpoint_id,
            title,
            severity,
            score,
            RemediationStatus.OPEN,
            now + timedelta(seconds=offset),
        )
        await repo.add(finding, None)
        findings.append(finding)
    scans = PostgresScanRepository(pool)
    running = scan.start(now)
    await scans.save(running)
    await scans.save(running.finish(status, now))
    return scan, findings


async def test_listing_filters_cursor_and_lifecycle(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    world = await seed_world(migrated_pool)
    repo = PostgresFindingQueryRepository(migrated_pool)
    scan, findings = await _scan_with_findings(
        migrated_pool,
        world,
        [
            ("a", Severity.CRITICAL, 100.0),
            ("b", Severity.HIGH, 70.0),
            ("c", Severity.MEDIUM, 45.0),
            ("d", Severity.LOW, None),
            ("e", Severity.INFO, 5.0),
        ],
    )
    owner = world.user.id
    titles: list[str] = []
    cursor = None
    while True:
        page = await repo.list_page(owner, FindingFilter(), FindingSort.PRIORITY, cursor, 2)
        titles += [v.finding.title for v in page.items]
        cursor = page.next_cursor
        if cursor is None:
            break
    assert titles == ["a", "b", "c", "e", "d"]

    detected: list[str] = []
    cursor = None
    while True:
        page = await repo.list_page(owner, FindingFilter(), FindingSort.DETECTED, cursor, 2)
        detected += [v.finding.title for v in page.items]
        cursor = page.next_cursor
        if cursor is None:
            break
    assert detected == ["e", "d", "c", "b", "a"]

    only_high = await repo.list_page(
        owner, FindingFilter(severity=Severity.HIGH), FindingSort.PRIORITY, None, 10
    )
    assert [v.finding.title for v in only_high.items] == ["b"]
    assert only_high.items[0].lifecycle is FindingLifecycle.IN_ANALYSIS
    in_analysis = await repo.list_page(
        owner,
        FindingFilter(lifecycle=FindingLifecycle.IN_ANALYSIS, scan_id=scan.id),
        FindingSort.PRIORITY,
        None,
        10,
    )
    assert len(in_analysis.items) == 5
    confirmed = await repo.list_page(
        owner, FindingFilter(lifecycle=FindingLifecycle.CONFIRMED), FindingSort.PRIORITY, None, 10
    )
    assert confirmed.items == []
    assert (
        await repo.list_page(uuid4(), FindingFilter(), FindingSort.PRIORITY, None, 10)
    ).items == []
    by_asset = await repo.list_page(
        None, FindingFilter(asset_id=world.asset_id), FindingSort.PRIORITY, None, 10
    )
    assert len(by_asset.items) == 5
    by_domain = await repo.list_page(
        None, FindingFilter(domain_id=world.domain.id), FindingSort.PRIORITY, None, 10
    )
    assert len(by_domain.items) == 5
    with pytest.raises(InvalidCursorError):
        await repo.list_page(owner, FindingFilter(), FindingSort.PRIORITY, "nope", 10)

    now = datetime.now(UTC)
    report = Report(uuid4(), scan.id, None, "resumen", "contenido", now)
    await PostgresReportRepository(migrated_pool).add(
        report,
        [Recommendation(uuid4(), report.id, findings[0].id, 1, "x", RecommendationStatus.PENDING)],
    )
    view = await repo.get(findings[0].id)
    assert view is not None
    assert view.has_report is True
    assert view.lifecycle is FindingLifecycle.CONFIRMED
    assert view.domain_name == "example.com"
    assert view.url == "https://example.com/"

    await repo.set_remediation(findings[0].id, RemediationStatus.FIXED)
    fixed = await repo.get(findings[0].id)
    assert fixed is not None
    assert fixed.lifecycle is FindingLifecycle.RESOLVED
    assert clamp_limit(5) == 5


async def test_counts_use_the_latest_finished_scan_and_exclude_false_positives(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    world = await seed_world(migrated_pool)
    repo = PostgresFindingQueryRepository(migrated_pool)
    older = datetime.now(UTC) - timedelta(days=1)
    old_scan, _ = await _scan_with_findings(
        migrated_pool, world, [("viejo", Severity.CRITICAL, 90.0)], created=older
    )
    new_scan, new = await _scan_with_findings(
        migrated_pool,
        world,
        [("n1", Severity.HIGH, 70.0), ("n2", Severity.HIGH, 70.0), ("fp", Severity.LOW, 20.0)],
    )
    async with migrated_pool.connection() as conn:
        await conn.execute(
            "insert into public.llm_decisions (id, scan_id, kind, model, input_hash, output_json, "
            "validated, justification) values (%s, %s, 'false_positive', 'm', %s, '{}'::jsonb, "
            "true, 'ok')",
            (decision := uuid4(), new_scan.id, "0" * 64),
        )
        await conn.execute(
            "update public.findings set is_false_positive = true, fp_justification = 'no aplica', "
            "decision_id = %s where id = %s",
            (decision, new[2].id),
        )
    latest = await repo.severity_counts(Scope(owner_id=world.user.id))
    assert latest == {Severity.HIGH: 2}
    explicit_old = await repo.severity_counts(Scope(scan_id=old_scan.id))
    assert explicit_old == {Severity.CRITICAL: 1}
    assert await repo.severity_counts(Scope(owner_id=uuid4())) == {}
    assert await repo.remediation_counts(Scope(scan_id=new_scan.id)) == {RemediationStatus.OPEN: 2}
    assert [v.finding.title for v in await repo.latest(Scope(owner_id=world.user.id), 5)] == [
        "n2",
        "n1",
    ]
    assert await repo.asset_count(Scope(owner_id=world.user.id)) == 1
    assert await repo.asset_count(Scope(owner_id=uuid4())) == 0
    statuses = await repo.scan_status_counts(Scope(owner_id=world.user.id))
    assert statuses == {JobStatus.DONE: 3}
