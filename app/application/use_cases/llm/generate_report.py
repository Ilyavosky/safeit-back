from uuid import UUID, uuid4

import structlog

from app.application.llm_budget import TokenBudget
from app.application.ports.clock import Clock
from app.application.ports.llm import (
    FindingReviewRepository,
    LlmGateway,
    ReportFindingView,
    ReportRequest,
    ReviewItem,
)
from app.application.ports.reports import ReportRepository
from app.application.ports.repositories import DomainRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.llm.recorder import DecisionRecorder
from app.domain.entities.report import Recommendation, Report
from app.domain.entities.scan import Scan
from app.domain.errors import DomainError
from app.domain.services.report_builder import (
    build_content,
    fallback_action,
    fallback_summary,
    severity_counts,
)
from app.domain.value_objects.llm_kind import LlmKind
from app.domain.value_objects.recommendation_status import RecommendationStatus
from app.domain.value_objects.severity import Severity

log = structlog.get_logger(__name__)

MAX_RECOMMENDATIONS = 100
MAX_ACTION = 1000


class GenerateReport:
    def __init__(
        self,
        *,
        domains: DomainRepository,
        review: FindingReviewRepository,
        reports: ReportRepository,
        gateway: LlmGateway | None,
        recorder: DecisionRecorder,
        budget: TokenBudget,
        audit: RecordAction,
        clock: Clock,
    ) -> None:
        self._domains = domains
        self._review = review
        self._reports = reports
        self._gateway = gateway
        self._recorder = recorder
        self._budget = budget
        self._audit = audit
        self._clock = clock

    async def execute(self, scan: Scan) -> Report | None:
        existing = await self._reports.get_by_scan(scan.id)
        if existing is not None:
            return existing
        domain = await self._domains.get_by_id(scan.domain_id)
        if domain is None:
            return None
        items = sorted(
            await self._review.list_for_review(scan.id),
            key=lambda i: (-(i.finding.priority_score or 0.0), str(i.finding.id)),
        )
        counts = severity_counts([i.finding.severity for i in items])
        summary, actions, decision_id = await self._draft(scan, domain.name, items, counts)
        report_id = uuid4()
        recommendations = [
            Recommendation(
                uuid4(), report_id, finding_id, number, action, RecommendationStatus.PENDING
            )
            for number, (finding_id, action) in enumerate(actions, start=1)
        ]
        report = Report(
            report_id,
            scan.id,
            decision_id,
            summary,
            build_content(summary, [(r.priority, r.action) for r in recommendations]),
            self._clock.now(),
        )
        await self._reports.add(report, recommendations)
        await self._audit.execute(
            "scan.report_generated",
            user_id=scan.started_by,
            entity="scan",
            entity_id=scan.id,
            detail={
                "findings": len(items),
                "recommendations": len(recommendations),
                "llm": decision_id is not None,
            },
        )
        return report

    async def _draft(
        self, scan: Scan, domain: str, items: list[ReviewItem], counts: dict[Severity, int]
    ) -> tuple[str, list[tuple[UUID, str]], UUID | None]:
        fallback_actions = [
            (i.finding.id, fallback_action(i.finding.title, i.url))
            for i in items[:MAX_RECOMMENDATIONS]
        ]
        fallback = (fallback_summary(domain, counts), fallback_actions, None)
        if self._gateway is None or not items or not self._budget.has_room(scan.id):
            return fallback
        request = ReportRequest(
            domain=domain,
            counts={severity.value: number for severity, number in counts.items()},
            findings=tuple(
                ReportFindingView(
                    i.finding.id,
                    i.finding.title,
                    i.finding.severity,
                    i.finding.priority_score,
                    i.url,
                )
                for i in items[:MAX_RECOMMENDATIONS]
            ),
        )
        try:
            response = await self._gateway.report(request)
        except DomainError as exc:
            log.warning("llm_report_unavailable", reason=exc.code)
            return fallback
        if response.data is None:
            await self._recorder.record(
                scan.id,
                LlmKind.REPORT,
                request,
                response,
                validated=False,
                justification=response.error,
            )
            return fallback
        known = {i.finding.id: i for i in items}
        seen: set[UUID] = set()
        drafts: list[tuple[int, float, UUID, str]] = []
        for rec in response.data.recommendations:
            action = rec.action.strip()[:MAX_ACTION]
            if rec.finding_id not in known or rec.finding_id in seen or not action:
                continue
            seen.add(rec.finding_id)
            score = known[rec.finding_id].finding.priority_score or 0.0
            drafts.append((rec.priority, -score, rec.finding_id, action))
        drafts.sort()
        decision = await self._recorder.record(
            scan.id,
            LlmKind.REPORT,
            request,
            response,
            validated=True,
            justification=f"Recomendaciones válidas: {len(drafts)}",
        )
        summary = response.data.summary.strip() or fallback[0]
        actions = [(d[2], d[3]) for d in drafts[:MAX_RECOMMENDATIONS]] or fallback_actions
        return summary, actions, decision.id
