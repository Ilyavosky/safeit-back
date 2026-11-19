from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any
from uuid import UUID

from app.domain.value_objects.job_status import JobStatus


@dataclass(frozen=True)
class TestRun:
    __test__ = False

    id: UUID
    scan_id: UUID
    endpoint_id: UUID
    tool_id: UUID
    tool_name: str
    params: dict[str, Any]
    status: JobStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    decision_id: UUID | None = None

    def start(self, at: datetime) -> "TestRun":
        return replace(self, status=JobStatus.RUNNING, started_at=at)

    def finish(self, status: JobStatus, at: datetime) -> "TestRun":
        return replace(self, status=status, finished_at=at)
