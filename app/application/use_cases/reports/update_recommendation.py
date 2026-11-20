from uuid import UUID

from app.application.ports.reports import ReportRepository
from app.application.ports.repositories import DomainRepository
from app.application.ports.testing_repositories import ScanRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.reports.access import load_scan
from app.domain.entities.report import Recommendation
from app.domain.entities.user import User
from app.domain.errors import EntityNotFoundError
from app.domain.value_objects.recommendation_status import RecommendationStatus


class UpdateRecommendationStatus:
    def __init__(
        self,
        domains: DomainRepository,
        scans: ScanRepository,
        reports: ReportRepository,
        audit: RecordAction,
    ) -> None:
        self._domains = domains
        self._scans = scans
        self._reports = reports
        self._audit = audit

    async def execute(
        self, user: User, recommendation_id: UUID, status: RecommendationStatus
    ) -> Recommendation:
        ref = await self._reports.get_recommendation(recommendation_id)
        if ref is None:
            raise EntityNotFoundError("recommendation", recommendation_id)
        await load_scan(self._domains, self._scans, user, ref.scan_id)
        previous = ref.recommendation.status
        if previous is not status:
            await self._reports.set_recommendation_status(recommendation_id, status)
            await self._audit.execute(
                "recommendation.status_changed",
                user_id=user.id,
                entity="recommendation",
                entity_id=recommendation_id,
                detail={"from": previous.value, "to": status.value},
            )
        return Recommendation(
            ref.recommendation.id,
            ref.recommendation.report_id,
            ref.recommendation.finding_id,
            ref.recommendation.priority,
            ref.recommendation.action,
            status,
        )
