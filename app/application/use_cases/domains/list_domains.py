from app.application.ports.repositories import DomainRepository
from app.domain.entities.domain import Domain
from app.domain.entities.user import User
from app.domain.value_objects.role import Role


class ListDomains:
    def __init__(self, domains: DomainRepository) -> None:
        self._domains = domains

    async def execute(self, user: User) -> list[Domain]:
        if user.role is Role.ADMIN:
            return await self._domains.list_all()
        return await self._domains.list_by_user(user.id)
