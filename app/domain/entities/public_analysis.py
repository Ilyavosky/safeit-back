from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any
from uuid import UUID

from app.domain.value_objects.host_kind import HostKind
from app.domain.value_objects.job_status import JobStatus


@dataclass(frozen=True)
class PublicHost:
    host: str
    kind: HostKind
    http_status: int | None = None
    title: str | None = None
    technologies: tuple[str, ...] = ()
    provider: str | None = None
    redirect_host: str | None = None
    security_headers: tuple[str, ...] = ()
    tls_issuer: str | None = None
    tls_valid: bool | None = None
    tls_valid_until: datetime | None = None
    id: UUID | None = None


@dataclass(frozen=True)
class PublicAnalysis:
    id: UUID
    user_id: UUID
    domain: str
    status: JobStatus
    created_at: datetime
    expires_at: datetime
    summary: str | None = None
    summary_model: str | None = None
    stats: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    finished_at: datetime | None = None

    def start(self) -> "PublicAnalysis":
        return replace(self, status=JobStatus.RUNNING)

    def finish(
        self,
        status: JobStatus,
        now: datetime,
        *,
        stats: dict[str, Any] | None = None,
        summary: str | None = None,
        summary_model: str | None = None,
        error: str | None = None,
    ) -> "PublicAnalysis":
        return replace(
            self,
            status=status,
            finished_at=now,
            stats=stats if stats is not None else self.stats,
            summary=summary,
            summary_model=summary_model,
            error=error,
        )
