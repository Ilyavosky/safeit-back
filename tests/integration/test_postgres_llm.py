from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import psycopg
import pytest
from psycopg_pool import AsyncConnectionPool

from app.application.llm_budget import TokenBudget
from app.application.ports.testing import ToolOutput
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.cve.lookup_cve import LookupCve
from app.application.use_cases.llm.analyze_findings import AnalyzeFindings
from app.application.use_cases.llm.finalize_scan import FinalizeScan
from app.application.use_cases.llm.generate_report import GenerateReport
from app.application.use_cases.llm.plan_source import FixedPlanSource, LlmPlanSource
from app.application.use_cases.llm.recorder import DecisionRecorder
from app.application.use_cases.testing.run_scan_tests import RunScanTests
from app.domain.entities.cve import CveRecord
from app.domain.entities.llm_proposals import (
    CorrelationItem,
    CorrelationProposal,
    FalsePositiveProposal,
    FalsePositiveVerdict,
    PlanProposal,
    ProposedTest,
    RecommendationDraft,
    ReportDraft,
)
from app.domain.entities.raw_finding import RawFinding
from app.domain.entities.scan import Scan
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.recommendation_status import RecommendationStatus
from app.domain.value_objects.scan_type import ScanType
from app.domain.value_objects.severity import Severity
from app.infrastructure.db.audit_repository import PostgresAuditRepository
from app.infrastructure.db.cve_repository import PostgresCveRepository
from app.infrastructure.db.domain_repository import PostgresDomainRepository
from app.infrastructure.db.endpoint_repository import PostgresEndpointRepository
from app.infrastructure.db.finding_repository import PostgresFindingRepository
from app.infrastructure.db.finding_review_repository import PostgresFindingReviewRepository
from app.infrastructure.db.llm_decision_repository import PostgresLlmDecisionRepository
from app.infrastructure.db.report_repository import PostgresReportRepository
from app.infrastructure.db.scan_repository import PostgresScanRepository
from app.infrastructure.db.test_run_repository import PostgresTestRunRepository
from app.infrastructure.db.tool_repository import PostgresToolRepository
from app.infrastructure.security.aes_gcm_cipher import AesGcmCipher
from app.infrastructure.testing.fixed_planner import FixedProbePlanner
from tests.fakes import FakeClock
from tests.fakes_cve import FakeEpss, FakeKev, FakeNvd
from tests.fakes_llm import FakeLlmGateway
from tests.fakes_testing import FakeRegistry, FakeRunner
from tests.pg_seed import seed_world
from tests.unit.test_secret_cipher import KEY

LOG4J = "CVE-2021-44228"


async def test_pipeline_end_to_end_on_postgres(migrated_pool: AsyncConnectionPool[Any]) -> None:
    world = await seed_world(migrated_pool)
    clock = FakeClock()
    pool = migrated_pool
    cves = PostgresCveRepository(pool)
    await cves.upsert_changed([CveRecord(LOG4J, 10.0, None, 0.94, True, clock.now())])
    runners = {name: FakeRunner() for name in ("headers", "testssl", "nuclei")}
    runners["headers"].output = ToolOutput(
        [
            RawFinding("Falta CSP", Severity.MEDIUM, "sin csp"),
            RawFinding("Banner Apache", Severity.LOW, "Apache/2.4.49"),
        ],
        "ok",
    )
    llm = FakeLlmGateway()
    llm.plan_data = PlanProposal((ProposedTest(world.endpoint_id, "headers", {}),), "solo headers")
    decisions = PostgresLlmDecisionRepository(pool)
    review = PostgresFindingReviewRepository(pool)
    reports = PostgresReportRepository(pool)
    budget = TokenBudget(100_000)
    recorder = DecisionRecorder(decisions, budget, clock)
    audit = RecordAction(PostgresAuditRepository(pool))
    domains = PostgresDomainRepository(pool)
    scans = PostgresScanRepository(pool)
    runs = PostgresTestRunRepository(pool)
    use_case = RunScanTests(
        domains=domains,
        scans=scans,
        endpoints=PostgresEndpointRepository(pool),
        tools=PostgresToolRepository(pool),
        test_runs=runs,
        findings=PostgresFindingRepository(pool),
        cves=cves,
        lookup_cve=LookupCve(cves, FakeNvd(), FakeEpss(), FakeKev(), clock),
        registry=FakeRegistry(runners),
        plan_source=LlmPlanSource(llm, recorder, budget, FixedPlanSource(FixedProbePlanner())),
        cipher=AesGcmCipher(KEY),
        audit=audit,
        clock=clock,
    )
    scan = Scan(
        uuid4(), world.domain.id, world.user.id, ScanType.TESTS, JobStatus.QUEUED, clock.now()
    )
    await scans.add(scan)
    done = await use_case.execute(scan.id)
    assert done is not None
    assert done.status is JobStatus.DONE

    stored = await runs.list_by_scan(scan.id)
    assert [r.tool_name for r in stored] == ["headers"]
    plan = [d for d in await decisions.list_by_scan(scan.id) if d.kind.value == "plan"]
    assert len(plan) == 1
    assert plan[0].validated is True
    assert stored[0].decision_id == plan[0].id

    items = await review.list_for_review(scan.id)
    by_title = {i.finding.title: i.finding.id for i in items}
    llm.correlation_data = CorrelationProposal(
        (CorrelationItem(by_title["Banner Apache"], (LOG4J, "CVE-2099-0001"), "x"),)
    )
    llm.false_positive_data = FalsePositiveProposal(
        (FalsePositiveVerdict(by_title["Falta CSP"], True, "CSP lo aplica el CDN."),)
    )
    llm.report_data = ReportDraft(
        "Resumen.", (RecommendationDraft(by_title["Banner Apache"], 1, "Ocultar versión."),)
    )
    finalize = FinalizeScan(
        scans,
        AnalyzeFindings(
            domains=domains,
            review=review,
            cves=cves,
            gateway=llm,
            recorder=recorder,
            budget=budget,
            cipher=AesGcmCipher(KEY),
            audit=audit,
        ),
        GenerateReport(
            domains=domains,
            review=review,
            reports=reports,
            gateway=llm,
            recorder=recorder,
            budget=budget,
            audit=audit,
            clock=clock,
        ),
        audit,
        30,
    )
    await finalize.execute(scan.id)

    remaining = await review.list_for_review(scan.id)
    assert [i.finding.title for i in remaining] == ["Banner Apache"]
    assert remaining[0].finding.cve_ids == (LOG4J,)
    assert remaining[0].finding.priority_score == 100.0
    kinds = sorted((d.kind.value, d.validated) for d in await decisions.list_by_scan(scan.id))
    assert kinds == [
        ("correlation", True),
        ("false_positive", True),
        ("plan", True),
        ("report", True),
    ]
    report = await reports.get_by_scan(scan.id)
    assert report is not None
    assert report.decision_id is not None
    recs = await reports.list_recommendations(report.id)
    assert [(r.priority, r.action, r.status) for r in recs] == [
        (1, "Ocultar versión.", RecommendationStatus.PENDING)
    ]
    ref = await reports.get_recommendation(recs[0].id)
    assert ref is not None
    assert ref.scan_id == scan.id
    await reports.set_recommendation_status(recs[0].id, RecommendationStatus.DONE)
    again = await reports.list_recommendations(report.id)
    assert again[0].status is RecommendationStatus.DONE
    async with pool.connection() as conn:
        cursor = await conn.execute(
            "select fp_justification from public.findings where is_false_positive"
        )
        row = await cursor.fetchone()
    assert row == ("CSP lo aplica el CDN.",)


async def test_unvalidated_plan_cannot_back_a_test_run(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    world = await seed_world(migrated_pool)
    pool = migrated_pool
    scan_id = uuid4()
    await PostgresScanRepository(pool).add(
        Scan(
            scan_id,
            world.domain.id,
            world.user.id,
            ScanType.TESTS,
            JobStatus.QUEUED,
            datetime.now(UTC),
        )
    )
    decisions = PostgresLlmDecisionRepository(pool)
    from app.domain.entities.llm_decision import LlmDecision
    from app.domain.value_objects.llm_kind import LlmKind

    bad = LlmDecision(
        uuid4(),
        scan_id,
        LlmKind.PLAN,
        "m",
        "0" * 64,
        {"x": 1},
        False,
        "rechazado",
        datetime.now(UTC),
    )
    await decisions.add(bad)
    from app.domain.entities.test_run import TestRun

    run = TestRun(
        uuid4(),
        scan_id,
        world.endpoint_id,
        world.tool_ids["headers"],
        "headers",
        {},
        JobStatus.QUEUED,
        decision_id=bad.id,
    )
    with pytest.raises(psycopg.errors.Error):
        await PostgresTestRunRepository(pool).add(run)
