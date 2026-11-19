from uuid import UUID

from app.application.ports.repositories import DomainRepository
from app.domain.entities.domain import Domain
from app.domain.entities.user import User
from app.domain.errors import EntityNotFoundError
from app.domain.value_objects.role import Role


async def load_domain(
    domains: DomainRepository, user: User, domain_id: UUID, *, owner_only: bool
) -> Domain:
    domain = await domains.get_by_id(domain_id)
    if domain is None:
        raise EntityNotFoundError("domain", domain_id)
    if domain.user_id == user.id:
        return domain
    if not owner_only and user.role is Role.ADMIN:
        return domain
    raise EntityNotFoundError("domain", domain_id)
