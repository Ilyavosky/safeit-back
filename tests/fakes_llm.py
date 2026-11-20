from collections.abc import Sequence
from dataclasses import replace
from typing import Any
from uuid import UUID

from app.application.ports.llm import (
    LlmResponse,
    PlanRequest,
    PublicSummaryRequest,
    ReportRequest,
    ReviewItem,
    ReviewRequest,
)
from app.application.ports.reports import RecommendationRef
from app.domain.entities.llm_decision import LlmDecision
from app.domain.entities.llm_proposals import (
    CorrelationProposal,
    FalsePositiveProposal,
    PlanProposal,
    PublicSummaryDraft,
    ReportDraft,
)
from app.domain.entities.report import Recommendation, Report
from app.domain.errors_llm import LlmUnavailableError
from app.domain.value_objects.recommendation_status import RecommendationStatus
from tests.fakes_testing import (
    InMemoryEndpointRepository,
    InMemoryFindingRepository,
    InMemoryTestRunRepository,
)


class FakeLlmGateway:
    model = "fake-model"

    def __init__(self) -> None:
        self.plan_data: PlanProposal | None = None
        self.correlation_data: CorrelationProposal | None = None
        self.false_positive_data: FalsePositiveProposal | None = None
        self.report_data: ReportDraft | None = None
        self.public_data: PublicSummaryDraft | None = None
        self.raw: Any = {"fake": True}
        self.tokens = 100
        self.unavailable = False
        self.calls: list[tuple[str, Any]] = []

    def _respond[T](self, name: str, request: Any, data: T | None) -> LlmResponse[T]:
        self.calls.append((name, request))
        if self.unavailable:
            raise LlmUnavailableError
        error = None if data is not None else "sin datos"
        return LlmResponse(self.model, self.tokens, self.raw, data, error)

    async def plan(self, request: PlanRequest) -> LlmResponse[PlanProposal]:
        return self._respond("plan", request, self.plan_data)

    async def correlate(self, request: ReviewRequest) -> LlmResponse[CorrelationProposal]:
        return self._respond("correlate", request, self.correlation_data)

    async def explain_public(
        self, request: PublicSummaryRequest
    ) -> LlmResponse[PublicSummaryDraft]:
        return self._respond("public", request, self.public_data)

    async def review_false_positives(
        self, request: ReviewRequest
    ) -> LlmResponse[FalsePositiveProposal]:
        return self._respond("false_positive", request, self.false_positive_data)

    async def report(self, request: ReportRequest) -> LlmResponse[ReportDraft]:
        return self._respond("report", request, self.report_data)


class InMemoryLlmDecisionRepository:
    def __init__(self) -> None:
        self.decisions: list[LlmDecision] = []

    async def add(self, decision: LlmDecision) -> None:
        self.decisions.append(decision)

    async def list_by_scan(self, scan_id: UUID) -> list[LlmDecision]:
        return [d for d in self.decisions if d.scan_id == scan_id]


class InMemoryFindingReviewRepository:
    def __init__(
        self,
        findings: InMemoryFindingRepository,
        test_runs: InMemoryTestRunRepository,
        endpoints: InMemoryEndpointRepository,
    ) -> None:
        self._findings = findings
        self._test_runs = test_runs
        self._endpoints = endpoints
        self.false_positive_reasons: dict[UUID, str] = {}

    async def list_for_review(self, scan_id: UUID) -> list[ReviewItem]:
        runs = {r.id: r for r in await self._test_runs.list_by_scan(scan_id)}
        urls = {e.id: e.url for e in self._endpoints.endpoints}
        items = [
            ReviewItem(
                finding=f,
                tool_name=runs[f.test_run_id].tool_name,
                url=urls.get(f.endpoint_id, ""),
                evidence_enc=self._findings.evidence.get(f.id),
            )
            for f in self._findings.findings
            if f.test_run_id in runs and not f.is_false_positive
        ]
        return sorted(items, key=lambda i: (-(i.finding.priority_score or 0.0), str(i.finding.id)))

    async def attach_cves(
        self, finding_id: UUID, cve_ids: Sequence[str], priority: float | None
    ) -> None:
        self._replace(finding_id, cve_ids=tuple(cve_ids), priority_score=priority)

    async def mark_false_positive(
        self, finding_id: UUID, justification: str, decision_id: UUID
    ) -> None:
        self.false_positive_reasons[finding_id] = justification
        self._replace(finding_id, is_false_positive=True)

    def _replace(self, finding_id: UUID, **changes: Any) -> None:
        for index, finding in enumerate(self._findings.findings):
            if finding.id == finding_id:
                self._findings.findings[index] = replace(finding, **changes)


class InMemoryReportRepository:
    def __init__(self) -> None:
        self.reports: dict[UUID, Report] = {}
        self.recommendations: dict[UUID, Recommendation] = {}

    async def get_by_scan(self, scan_id: UUID) -> Report | None:
        return next((r for r in self.reports.values() if r.scan_id == scan_id), None)

    async def add(self, report: Report, recommendations: Sequence[Recommendation]) -> None:
        self.reports[report.id] = report
        for rec in recommendations:
            self.recommendations[rec.id] = rec

    async def list_recommendations(self, report_id: UUID) -> list[Recommendation]:
        found = [r for r in self.recommendations.values() if r.report_id == report_id]
        return sorted(found, key=lambda r: (r.priority, str(r.id)))

    async def get_recommendation(self, recommendation_id: UUID) -> RecommendationRef | None:
        rec = self.recommendations.get(recommendation_id)
        if rec is None:
            return None
        return RecommendationRef(rec, self.reports[rec.report_id].scan_id)

    async def set_recommendation_status(
        self, recommendation_id: UUID, status: RecommendationStatus
    ) -> None:
        self.recommendations[recommendation_id] = replace(
            self.recommendations[recommendation_id], status=status
        )
