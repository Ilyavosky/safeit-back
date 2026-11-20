from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from uuid import UUID

from app.application.ports.public_analysis import ApexDns, WebObservation
from app.domain.entities.public_analysis import PublicAnalysis, PublicHost
from app.domain.errors_queue import QueueUnavailableError
from app.domain.value_objects.job_status import JobStatus

ACTIVE = {JobStatus.QUEUED, JobStatus.RUNNING}


class InMemoryPublicAnalysisRepository:
    def __init__(self) -> None:
        self.analyses: dict[UUID, PublicAnalysis] = {}
        self.hosts: dict[UUID, list[PublicHost]] = {}

    async def add_if_idle(self, analysis: PublicAnalysis) -> bool:
        if any(
            a.user_id == analysis.user_id and a.status in ACTIVE for a in self.analyses.values()
        ):
            return False
        self.analyses[analysis.id] = analysis
        return True

    async def save(self, analysis: PublicAnalysis) -> None:
        self.analyses[analysis.id] = analysis

    async def get(self, analysis_id: UUID) -> PublicAnalysis | None:
        return self.analyses.get(analysis_id)

    async def list_by_user(self, user_id: UUID, limit: int) -> list[PublicAnalysis]:
        items = [a for a in self.analyses.values() if a.user_id == user_id]
        return sorted(items, key=lambda a: a.created_at, reverse=True)[:limit]

    async def count_since(self, user_id: UUID, since: datetime) -> int:
        return sum(
            1 for a in self.analyses.values() if a.user_id == user_id and a.created_at >= since
        )

    async def fail_stale(self, user_id: UUID, cutoff: datetime) -> int:
        stale = [
            a
            for a in self.analyses.values()
            if a.user_id == user_id and a.status in ACTIVE and a.created_at < cutoff
        ]
        for analysis in stale:
            self.analyses[analysis.id] = replace(analysis, status=JobStatus.FAILED)
        return len(stale)

    async def replace_hosts(self, analysis_id: UUID, hosts: Sequence[PublicHost]) -> None:
        self.hosts[analysis_id] = list(hosts)

    async def list_hosts(self, analysis_id: UUID) -> list[PublicHost]:
        return list(self.hosts.get(analysis_id, []))

    async def delete_expired(self, now: datetime) -> int:
        expired = [a.id for a in self.analyses.values() if a.expires_at <= now]
        for analysis_id in expired:
            del self.analyses[analysis_id]
            self.hosts.pop(analysis_id, None)
        return len(expired)


class FakePublicQueue:
    def __init__(self) -> None:
        self.enqueued: list[UUID] = []
        self.unavailable = False

    async def enqueue(self, analysis_id: UUID) -> None:
        if self.unavailable:
            raise QueueUnavailableError
        self.enqueued.append(analysis_id)


class FakePublicDns:
    def __init__(self) -> None:
        self.apex_data = ApexDns(
            nameservers=("ns1.proveedor.net",),
            mail_hosts=("mx.ejemplo.com",),
            has_spf=True,
            has_dmarc=False,
            has_caa=False,
        )
        self.cname_data: dict[str, list[str]] = {}

    async def apex(self, domain: str) -> ApexDns:
        return self.apex_data

    async def cnames(self, host: str) -> list[str]:
        return self.cname_data.get(host, [])


class FakeCtSource:
    def __init__(self) -> None:
        self.names: list[str] = []

    async def subdomains(self, domain: str) -> list[str]:
        return list(self.names)


class FakeWebFetcher:
    def __init__(self) -> None:
        self.observations: dict[str, WebObservation | None] = {}
        self.fetched: list[str] = []

    async def fetch(self, host: str) -> WebObservation | None:
        self.fetched.append(host)
        return self.observations.get(host)
