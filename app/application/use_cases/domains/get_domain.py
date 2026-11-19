from uuid import UUID

from app.application.ports.repositories import DomainRepository
from app.application.use_cases.domains.access import load_domain
from app.domain.entities.domain import Domain
from app.domain.entities.user import User


class GetDomain:
    def __init__(self, domains: DomainRepository) -> None:
        self._domains = domains

    async def execute(self, user: User, domain_id: UUID) -> Domain:
        return await load_domain(self._domains, user, domain_id, owner_only=False)
