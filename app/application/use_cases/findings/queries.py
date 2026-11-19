from uuid import UUID

from app.application.pagination import clamp_limit
from app.application.ports.findings_query import (
    FindingFilter,
    FindingPage,
    FindingQueryRepository,
    FindingSort,
    FindingView,
)
from app.application.ports.repositories import DomainRepository
from app.application.use_cases.domains.access import load_domain
from app.domain.entities.user import User
from app.domain.errors import EntityNotFoundError
from app.domain.value_objects.role import Role


class ListFindings:
    def __init__(self, domains: DomainRepository, findings: FindingQueryRepository) -> None:
        self._domains = domains
        self._findings = findings

    async def execute(
        self,
        user: User,
        filters: FindingFilter,
        sort: FindingSort = FindingSort.PRIORITY,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> FindingPage:
        if filters.domain_id is not None:
            await load_domain(self._domains, user, filters.domain_id, owner_only=False)
        owner_id = None if user.role is Role.ADMIN else user.id
        return await self._findings.list_page(owner_id, filters, sort, cursor, clamp_limit(limit))


class GetFinding:
    def __init__(self, domains: DomainRepository, findings: FindingQueryRepository) -> None:
        self._domains = domains
        self._findings = findings

    async def execute(self, user: User, finding_id: UUID) -> FindingView:
        view = await self._findings.get(finding_id)
        if view is None:
            raise EntityNotFoundError("finding", finding_id)
        await _ensure_access(self._domains, user, view, finding_id)
        return view


async def _ensure_access(
    domains: DomainRepository, user: User, view: FindingView, finding_id: UUID
) -> None:
    try:
        await load_domain(domains, user, view.domain_id, owner_only=False)
    except EntityNotFoundError as exc:
        raise EntityNotFoundError("finding", finding_id) from exc
