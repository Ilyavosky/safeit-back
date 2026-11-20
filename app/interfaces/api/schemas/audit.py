from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel


class AuditEntryResponse(BaseModel):
    id: int
    user_id: UUID | None
    action: str
    entity: str | None
    entity_id: UUID | None
    detail: dict[str, Any]
    prev_hash: str | None
    hash: str
    created_at: datetime


class AuditChainResponse(BaseModel):
    intact: bool
    broken_at_id: int | None
