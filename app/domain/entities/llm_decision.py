from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.domain.value_objects.llm_kind import LlmKind


@dataclass(frozen=True)
class LlmDecision:
    id: UUID
    scan_id: UUID
    kind: LlmKind
    model: str
    input_hash: str
    output: dict[str, Any]
    validated: bool
    justification: str | None
    created_at: datetime
