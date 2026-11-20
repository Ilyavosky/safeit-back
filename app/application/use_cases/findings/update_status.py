from uuid import UUID

from app.application.ports.findings_query import FindingQueryRepository, FindingView
from app.application.ports.repositories import DomainRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.findings.queries import GetFinding
from app.domain.entities.user import User
from app.domain.errors import EntityNotFoundError
from app.domain.services.finding_status import ensure_transition
from app.domain.value_objects.remediation_status import RemediationStatus


class UpdateFindingStatus:
    def __init__(
        self, domains: DomainRepository, findings: FindingQueryRepository, audit: RecordAction
    ) -> None:
        self._get = GetFinding(domains, findings)
        self._findings = findings
        self._audit = audit

    async def execute(
        self, user: User, finding_id: UUID, target: RemediationStatus, reason: str | None
    ) -> FindingView:
        view = await self._get.execute(user, finding_id)
        current = view.finding.remediation_status
        ensure_transition(current, target, reason, is_false_positive=view.finding.is_false_positive)
        await self._findings.set_remediation(finding_id, target)
        await self._audit.execute(
            "finding.status_changed",
            user_id=user.id,
            entity="finding",
            entity_id=finding_id,
            detail={
                "from": current.value,
                "to": target.value,
                "reason": (reason or "").strip()[:500] or None,
            },
        )
        updated = await self._findings.get(finding_id)
        if updated is None:
            raise EntityNotFoundError("finding", finding_id)
        return updated
