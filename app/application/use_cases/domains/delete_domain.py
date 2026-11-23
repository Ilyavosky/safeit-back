from uuid import UUID

from app.application.ports.repositories import DomainRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.domains.access import load_domain
from app.domain.entities.user import User


class DeleteDomain:
    def __init__(self, domains: DomainRepository, audit: RecordAction) -> None:
        self._domains = domains
        self._audit = audit

    async def execute(self, user: User, domain_id: UUID) -> None:
        domain = await load_domain(self._domains, user, domain_id, owner_only=True)
        await self._domains.delete(domain.id)
        await self._audit.execute(
            "domain.deleted",
            user_id=user.id,
            entity="domain",
            entity_id=domain.id,
            detail={"name": domain.name, "status": domain.status.value},
        )
