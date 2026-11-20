from uuid import UUID

from app.application.ports.repositories import AuditRepository
from app.domain.entities.audit_entry import AuditEntry

MAX_PAGE_SIZE = 200


class ListAudit:
    def __init__(self, audit: AuditRepository) -> None:
        self._audit = audit

    async def execute(
        self,
        *,
        limit: int = 50,
        before_id: int | None = None,
        user_id: UUID | None = None,
        action: str | None = None,
    ) -> list[AuditEntry]:
        return await self._audit.list_entries(
            limit=max(1, min(limit, MAX_PAGE_SIZE)),
            before_id=before_id,
            user_id=user_id,
            action=action,
        )
