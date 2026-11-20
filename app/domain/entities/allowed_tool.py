from dataclasses import dataclass
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class AllowedTool:
    id: UUID
    name: str
    allowed_params: dict[str, Any]
    active: bool
