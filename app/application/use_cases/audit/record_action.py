from collections.abc import Mapping
from typing import Any
from uuid import UUID

from app.application.ports.repositories import AuditRepository


class RecordAction:
    def __init__(self, audit: AuditRepository) -> None:
        self._audit = audit

    async def execute(
        self,
        action: str,
        *,
        user_id: UUID | None = None,
        entity: str | None = None,
        entity_id: UUID | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        await self._audit.record(
            user_id=user_id,
            action=action,
            entity=entity,
            entity_id=entity_id,
            detail=detail or {},
        )
