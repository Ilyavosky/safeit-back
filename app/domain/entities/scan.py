from dataclasses import dataclass, replace
from datetime import datetime
from uuid import UUID

from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.scan_type import ScanType


@dataclass(frozen=True)
class Scan:
    id: UUID
    domain_id: UUID
    started_by: UUID
    type: ScanType
    status: JobStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    def start(self, at: datetime) -> "Scan":
        return replace(self, status=JobStatus.RUNNING, started_at=at)

    def finish(self, status: JobStatus, at: datetime) -> "Scan":
        return replace(self, status=status, finished_at=at)
