from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.application.use_cases.public.queries import PublicAnalysisDetail
from app.domain.entities.public_analysis import PublicAnalysis, PublicHost
from app.domain.value_objects.host_kind import HostKind
from app.domain.value_objects.job_status import JobStatus


class PublicAnalysisCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    accept_notice: bool


class PublicHostResponse(BaseModel):
    host: str
    kind: HostKind
    http_status: int | None
    title: str | None
    technologies: list[str]
    provider: str | None
    redirect_host: str | None
    security_headers: list[str]
    tls_issuer: str | None
    tls_valid: bool | None
    tls_valid_until: datetime | None

    @classmethod
    def from_host(cls, host: PublicHost) -> "PublicHostResponse":
        return cls(
            host=host.host,
            kind=host.kind,
            http_status=host.http_status,
            title=host.title,
            technologies=list(host.technologies),
            provider=host.provider,
            redirect_host=host.redirect_host,
            security_headers=list(host.security_headers),
            tls_issuer=host.tls_issuer,
            tls_valid=host.tls_valid,
            tls_valid_until=host.tls_valid_until,
        )


class PublicAnalysisResponse(BaseModel):
    id: UUID
    domain: str
    status: JobStatus
    summary: str | None
    summary_model: str | None
    stats: dict[str, Any]
    error: str | None
    created_at: datetime
    finished_at: datetime | None
    expires_at: datetime

    @classmethod
    def from_analysis(cls, analysis: PublicAnalysis) -> "PublicAnalysisResponse":
        return cls(
            id=analysis.id,
            domain=analysis.domain,
            status=analysis.status,
            summary=analysis.summary,
            summary_model=analysis.summary_model,
            stats=analysis.stats,
            error=analysis.error,
            created_at=analysis.created_at,
            finished_at=analysis.finished_at,
            expires_at=analysis.expires_at,
        )


class PublicAnalysisDetailResponse(PublicAnalysisResponse):
    hosts: list[PublicHostResponse]

    @classmethod
    def from_detail(cls, detail: PublicAnalysisDetail) -> "PublicAnalysisDetailResponse":
        base = PublicAnalysisResponse.from_analysis(detail.analysis)
        return cls(
            **base.model_dump(),
            hosts=[PublicHostResponse.from_host(host) for host in detail.hosts],
        )
