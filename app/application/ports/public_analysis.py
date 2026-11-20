from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.domain.entities.public_analysis import PublicAnalysis, PublicHost


@dataclass(frozen=True)
class ApexDns:
    nameservers: tuple[str, ...] = ()
    mail_hosts: tuple[str, ...] = ()
    has_spf: bool = False
    has_dmarc: bool = False
    has_caa: bool = False


@dataclass(frozen=True)
class TlsObservation:
    issuer: str | None
    valid: bool
    valid_until: datetime | None


@dataclass(frozen=True)
class WebObservation:
    http_status: int
    content_type: str | None = None
    title: str | None = None
    redirect_host: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    html_head: str = ""
    tls: TlsObservation | None = None


class PublicDns(Protocol):
    async def apex(self, domain: str) -> ApexDns: ...

    async def cnames(self, host: str) -> list[str]: ...


class CertTransparencySource(Protocol):
    async def subdomains(self, domain: str) -> list[str]: ...


class PublicWebFetcher(Protocol):
    async def fetch(self, host: str) -> WebObservation | None: ...


class PublicAnalysisQueue(Protocol):
    async def enqueue(self, analysis_id: UUID) -> None: ...


class PublicAnalysisRepository(Protocol):
    async def add_if_idle(self, analysis: PublicAnalysis) -> bool: ...

    async def save(self, analysis: PublicAnalysis) -> None: ...

    async def get(self, analysis_id: UUID) -> PublicAnalysis | None: ...

    async def list_by_user(self, user_id: UUID, limit: int) -> list[PublicAnalysis]: ...

    async def count_since(self, user_id: UUID, since: datetime) -> int: ...

    async def fail_stale(self, user_id: UUID, cutoff: datetime) -> int: ...

    async def replace_hosts(self, analysis_id: UUID, hosts: Sequence[PublicHost]) -> None: ...

    async def list_hosts(self, analysis_id: UUID) -> list[PublicHost]: ...

    async def delete_expired(self, now: datetime) -> int: ...
