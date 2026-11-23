from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from app.domain.entities.finding import Finding
from app.domain.services.finding_status import lifecycle_status
from app.domain.value_objects.finding_lifecycle import FindingLifecycle
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.severity import Severity


@dataclass(frozen=True)
class FindingView:
    finding: Finding
    domain_id: UUID
    domain_name: str
    asset_id: UUID
    asset_value: str
    url: str
    scan_id: UUID
    scan_status: JobStatus
    has_report: bool

    @property
    def lifecycle(self) -> FindingLifecycle:
        return lifecycle_status(
            self.finding.remediation_status,
            self.finding.is_false_positive,
            self.scan_status,
            self.has_report,
        )


class FindingSort(StrEnum):
    PRIORITY = "priority"
    DETECTED = "detected"


@dataclass(frozen=True)
class FindingFilter:
    severity: Severity | None = None
    lifecycle: FindingLifecycle | None = None
    asset_id: UUID | None = None
    domain_id: UUID | None = None
    scan_id: UUID | None = None


@dataclass(frozen=True)
class FindingPage:
    items: list[FindingView] = field(default_factory=list)
    next_cursor: str | None = None


@dataclass(frozen=True)
class Scope:
    owner_id: UUID | None = None
    domain_id: UUID | None = None
    scan_id: UUID | None = None


class FindingQueryRepository(Protocol):
    async def get(self, finding_id: UUID) -> FindingView | None: ...

    async def get_many(self, finding_ids: list[UUID]) -> dict[UUID, FindingView]: ...

    async def list_page(
        self,
        owner_id: UUID | None,
        filters: FindingFilter,
        sort: FindingSort,
        cursor: str | None,
        limit: int,
    ) -> FindingPage: ...

    async def set_remediation(self, finding_id: UUID, status: RemediationStatus) -> None: ...

    async def severity_counts(self, scope: Scope) -> dict[Severity, int]: ...

    async def remediation_counts(self, scope: Scope) -> dict[RemediationStatus, int]: ...

    async def latest(self, scope: Scope, limit: int) -> list[FindingView]: ...

    async def asset_count(self, scope: Scope) -> int: ...

    async def scan_status_counts(self, scope: Scope) -> dict[JobStatus, int]: ...

    async def latest_report_scan_id(self, owner_id: UUID | None) -> UUID | None: ...
