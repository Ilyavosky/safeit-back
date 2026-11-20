from collections.abc import Callable
from uuid import UUID, uuid4

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
from app.application.use_cases.testing.start_tests import StartTests
from app.domain.entities.cve import CveRecord
from app.domain.entities.endpoint import Endpoint
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
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.llm_kind import LlmKind
from app.domain.value_objects.severity import Severity
from app.infrastructure.security.aes_gcm_cipher import AesGcmCipher
from app.infrastructure.testing.fixed_planner import FixedProbePlanner
from tests.fakes_cve import FakeEpss, FakeKev, FakeNvd
from tests.fakes_llm import (
    FakeLlmGateway,
    InMemoryFindingReviewRepository,
    InMemoryLlmDecisionRepository,
    InMemoryReportRepository,
)
from tests.fakes_testing import FakeRegistry
from tests.unit.test_secret_cipher import KEY
from tests.unit.test_testing_use_cases import LOG4J, Env, _endpoint


class LlmEnv(Env):
    def __init__(self, *, budget: int = 10_000) -> None:
        super().__init__()
        self.llm = FakeLlmGateway()
        self.decisions = InMemoryLlmDecisionRepository()
        self.reports = InMemoryReportRepository()
        self.budget = TokenBudget(budget)
        self.review = InMemoryFindingReviewRepository(self.findings, self.test_runs, self.endpoints)
        audit = RecordAction(self.audit_repo)
        recorder = DecisionRecorder(self.decisions, self.budget, self.clock)
        fixed = FixedPlanSource(FixedProbePlanner())
        self.run = RunScanTests(
            domains=self.domains,
            scans=self.scans,
            endpoints=self.endpoints,
            tools=self.tools,
            test_runs=self.test_runs,
            findings=self.findings,
            cves=self.cves,
            lookup_cve=LookupCve(self.cves, FakeNvd(), FakeEpss(), FakeKev(), self.clock),
            registry=FakeRegistry(self.runners),
            plan_source=LlmPlanSource(self.llm, recorder, self.budget, fixed),
            cipher=AesGcmCipher(KEY),
            audit=audit,
            clock=self.clock,
        )
        self.generate = GenerateReport(
            domains=self.domains,
            review=self.review,
            reports=self.reports,
            gateway=self.llm,
            recorder=recorder,
            budget=self.budget,
            audit=audit,
            clock=self.clock,
        )
        self.analyze = AnalyzeFindings(
            domains=self.domains,
            review=self.review,
            cves=self.cves,
            gateway=self.llm,
            recorder=recorder,
            budget=self.budget,
            cipher=AesGcmCipher(KEY),
            audit=audit,
        )
        self.finalize = FinalizeScan(self.scans, self.analyze, self.generate, audit, 30)
        self.start = StartTests(
            self.domains,
            self.endpoints,
            self.scans,
            self.run,
            self.scheduler,
            audit,
            self.clock,
            self.finalize,
        )


async def _run_scan(env: LlmEnv) -> tuple[UUID, UUID]:
    domain = await env.with_domain()
    endpoint = _endpoint(domain, "https://example.com/")
    env.endpoints.endpoints = [endpoint]
    scan = await env.start.execute(env.owner, domain.id)
    await env.scheduler.run_all()
    return scan.id, endpoint.id


async def test_valid_llm_plan_is_recorded_and_linked_to_runs() -> None:
    env = LlmEnv()
    domain = await env.with_domain()
    endpoint = _endpoint(domain, "https://example.com/")
    env.endpoints.endpoints = [endpoint]
    env.llm.plan_data = PlanProposal((ProposedTest(endpoint.id, "headers", {}),), "solo cabeceras")
    scan = await env.start.execute(env.owner, domain.id)
    await env.scheduler.run_all()

    runs = await env.test_runs.list_by_scan(scan.id)
    assert [r.tool_name for r in runs] == ["headers"]
    plan = [d for d in env.decisions.decisions if d.kind is LlmKind.PLAN]
    assert len(plan) == 1
    assert plan[0].validated is True
    assert plan[0].justification == "solo cabeceras"
    assert runs[0].decision_id == plan[0].id
    assert len(plan[0].input_hash) == 64


async def test_invalid_plans_fall_back_to_fixed_planner() -> None:
    cases: list[Callable[[Endpoint], PlanProposal]] = [
        lambda e: PlanProposal((ProposedTest(uuid4(), "headers", {}),), "x"),
        lambda e: PlanProposal((ProposedTest(e.id, "bash", {"cmd": "rm -rf /"}),), "x"),
        lambda e: PlanProposal((ProposedTest(e.id, "nuclei", {"tags": ["dos"]}),), "x"),
        lambda e: PlanProposal((), "vacío"),
    ]
    for build in cases:
        env = LlmEnv()
        domain = await env.with_domain()
        endpoint = _endpoint(domain, "https://example.com/")
        env.endpoints.endpoints = [endpoint]
        env.llm.plan_data = build(endpoint)
        scan = await env.start.execute(env.owner, domain.id)
        await env.scheduler.run_all()
        assert env.scans.scans[scan.id].status is JobStatus.DONE
        runs = await env.test_runs.list_by_scan(scan.id)
        assert sorted(r.tool_name for r in runs) == ["headers", "nuclei", "testssl"]
        assert all(r.decision_id is None for r in runs)
        plan = [d for d in env.decisions.decisions if d.kind is LlmKind.PLAN]
        assert [d.validated for d in plan] == [False]


async def test_llm_cannot_raise_rate_limits_above_policy() -> None:
    env = LlmEnv()
    domain = await env.with_domain()
    endpoint = _endpoint(domain, "https://example.com/")
    env.endpoints.endpoints = [endpoint]
    env.llm.plan_data = PlanProposal(
        (ProposedTest(endpoint.id, "nuclei", {"rate_limit": 9999, "tags": ["cve"]}),), "x"
    )
    await env.start.execute(env.owner, domain.id)
    await env.scheduler.run_all()
    ((_, params),) = env.runners["nuclei"].calls
    assert params["rate_limit"] <= 50


async def test_non_whitelisted_endpoint_in_plan_is_rejected() -> None:
    env = LlmEnv()
    domain = await env.with_domain()
    good = _endpoint(domain, "https://example.com/")
    hidden = _endpoint(domain, "https://example.com/admin", whitelisted=False)
    env.endpoints.endpoints = [good, hidden]
    env.llm.plan_data = PlanProposal((ProposedTest(hidden.id, "headers", {}),), "x")
    scan = await env.start.execute(env.owner, domain.id)
    await env.scheduler.run_all()
    runs = await env.test_runs.list_by_scan(scan.id)
    assert all(r.endpoint_id == good.id for r in runs)


async def test_llm_outage_does_not_stop_the_scan() -> None:
    env = LlmEnv()
    env.llm.unavailable = True
    scan_id, _ = await _run_scan(env)
    assert env.scans.scans[scan_id].status is JobStatus.DONE
    assert env.decisions.decisions == []
    assert await env.reports.get_by_scan(scan_id) is not None


async def test_exhausted_budget_skips_llm_calls() -> None:
    env = LlmEnv(budget=1)
    domain = await env.with_domain()
    env.endpoints.endpoints = [_endpoint(domain, "https://example.com/")]
    scan = await env.start.execute(env.owner, domain.id)
    env.budget.spend(scan.id, 5)
    await env.scheduler.run_all()
    assert env.llm.calls == []
    assert env.scans.scans[scan.id].status is JobStatus.DONE


async def _with_findings(env: LlmEnv) -> tuple[UUID, dict[str, UUID]]:
    env.runners["headers"].output = ToolOutput(
        [RawFinding("Falta la cabecera CSP", Severity.MEDIUM, "sin CSP")], "ok"
    )
    env.runners["nuclei"].output = ToolOutput(
        [RawFinding("Versión expuesta", Severity.LOW, "Server: Apache/2.4.49")], "{}"
    )
    env.cves.records[LOG4J] = CveRecord(LOG4J, 10.0, None, 0.94, True, env.clock.now())
    scan_id, _ = await _run_scan(env)
    ids = {f.title: f.id for f in env.findings.findings}
    return scan_id, ids


async def test_correlation_only_keeps_cves_present_in_catalog() -> None:
    env = LlmEnv()
    env.llm.plan_data = None
    env.llm.correlation_data = CorrelationProposal(())
    domain = await env.with_domain()
    env.endpoints.endpoints = [_endpoint(domain, "https://example.com/")]
    env.runners["nuclei"].output = ToolOutput(
        [RawFinding("Versión expuesta", Severity.LOW, "Apache")], "{}"
    )
    env.cves.records[LOG4J] = CveRecord(LOG4J, 10.0, None, 0.94, True, env.clock.now())
    finding_ids: list[UUID] = []

    async def correlate_later() -> None:
        finding_ids.extend(f.id for f in env.findings.findings)
        env.llm.correlation_data = CorrelationProposal(
            (
                CorrelationItem(finding_ids[0], (LOG4J, "cve-2099-99999", "no-es-cve"), "x"),
                CorrelationItem(uuid4(), (LOG4J,), "desconocido"),
            )
        )

    await env.start.execute(env.owner, domain.id)
    await env.run.execute(next(iter(env.scans.scans)))
    await correlate_later()
    scan = next(iter(env.scans.scans.values()))
    await env.analyze.execute(scan)

    finding = env.findings.findings[0]
    assert finding.cve_ids == (LOG4J,)
    assert finding.priority_score == 100.0
    record = [d for d in env.decisions.decisions if d.kind is LlmKind.CORRELATION]
    assert [d.validated for d in record] == [True]
    assert "1" in (record[0].justification or "")


async def test_false_positive_requires_justification() -> None:
    env = LlmEnv()
    scan_id, ids = await _with_findings(env)
    env.llm.false_positive_data = FalsePositiveProposal(
        (
            FalsePositiveVerdict(ids["Falta la cabecera CSP"], True, "   "),
            FalsePositiveVerdict(ids["Versión expuesta"], True, "El banner es de un honeypot."),
        )
    )
    await env.analyze.execute(env.scans.scans[scan_id])
    flagged = {f.title: f.is_false_positive for f in env.findings.findings}
    assert flagged == {"Falta la cabecera CSP": False, "Versión expuesta": True}
    assert (
        env.review.false_positive_reasons[ids["Versión expuesta"]] == "El banner es de un honeypot."
    )


async def test_report_uses_llm_text_but_system_priorities_and_ids() -> None:
    env = LlmEnv()
    scan_id, ids = await _with_findings(env)
    env.generate._reports = InMemoryReportRepository()
    env.llm.report_data = ReportDraft(
        "Resumen del modelo.",
        (
            RecommendationDraft(ids["Falta la cabecera CSP"], 2, "Agregar CSP."),
            RecommendationDraft(ids["Versión expuesta"], 1, "Ocultar la versión."),
            RecommendationDraft(uuid4(), 3, "Inventada."),
            RecommendationDraft(ids["Versión expuesta"], 4, "Duplicada."),
        ),
    )
    report = await env.generate.execute(env.scans.scans[scan_id])
    assert report is not None
    assert report.summary == "Resumen del modelo."
    recs = await env.generate._reports.list_recommendations(report.id)
    assert [(r.priority, r.action) for r in recs] == [
        (1, "Ocultar la versión."),
        (2, "Agregar CSP."),
    ]
    assert report.decision_id is not None


async def test_report_falls_back_when_llm_returns_nothing() -> None:
    env = LlmEnv()
    scan_id, _ = await _with_findings(env)
    report = await env.reports.get_by_scan(scan_id)
    assert report is not None
    assert "2 hallazgos activos" in report.summary
    recs = await env.reports.list_recommendations(report.id)
    assert len(recs) == 2
    assert [r.priority for r in recs] == [1, 2]


async def test_report_is_generated_once_per_scan() -> None:
    env = LlmEnv()
    scan_id, _ = await _with_findings(env)
    first = await env.reports.get_by_scan(scan_id)
    again = await env.generate.execute(env.scans.scans[scan_id])
    assert again is not None
    assert first is not None
    assert again.id == first.id
    assert len(env.reports.reports) == 1


async def test_finalize_ignores_failed_scans() -> None:
    env = LlmEnv()
    env.runners["headers"].error = "x"
    env.runners["testssl"].error = "x"
    env.runners["nuclei"].error = "x"
    scan_id, _ = await _run_scan(env)
    assert env.scans.scans[scan_id].status is JobStatus.FAILED
    assert env.reports.reports == {}
