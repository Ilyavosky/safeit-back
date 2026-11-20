from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class AuditEntry:
    id: int
    user_id: UUID | None
    action: str
    entity: str | None
    entity_id: UUID | None
    detail: dict[str, Any]
    prev_hash: str | None
    hash: str
    created_at: datetime
