from dataclasses import dataclass, field
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class PlannedTest:
    endpoint_id: UUID
    tool_name: str
    params: dict[str, Any] = field(default_factory=dict)
