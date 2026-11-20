from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from uuid import UUID, uuid4

from app.application.ports.testing import ToolExecutionError
from app.domain.entities.asset import Asset
from app.domain.entities.discovered import DiscoveredService, HttpProbe
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.scan import Scan
from app.domain.errors_queue import QueueUnavailableError
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.scan_type import ScanType
from tests.fakes_testing import InMemoryEndpointRepository, InMemoryScanRepository


class InMemoryReconScanRepository:
    def __init__(self, scans: InMemoryScanRepository) -> None:
        self._scans = scans

    async def add_if_idle(self, scan: Scan) -> bool:
        busy = any(
            s.domain_id == scan.domain_id
            and s.type is ScanType.RECON
            and s.status in {JobStatus.QUEUED, JobStatus.RUNNING}
            for s in self._scans.scans.values()
        )
        if busy:
            return False
        await self._scans.add(scan)
        return True

    async def fail_stale(self, domain_id: UUID, cutoff: datetime) -> int:
        stale = [
            s
            for s in self._scans.scans.values()
            if s.domain_id == domain_id
            and s.type is ScanType.RECON
            and s.status in {JobStatus.QUEUED, JobStatus.RUNNING}
            and s.created_at < cutoff
        ]
        for scan in stale:
            self._scans.scans[scan.id] = replace(scan, status=JobStatus.FAILED)
        return len(stale)


class InMemoryAssetRepository:
    def __init__(self, endpoints: InMemoryEndpointRepository | None = None) -> None:
        self.assets: dict[UUID, Asset] = {}
        self.services: dict[UUID, list[DiscoveredService]] = {}
        self.endpoints: dict[UUID, Endpoint] = {}
        self._endpoint_repo = endpoints

    async def upsert(self, asset: Asset) -> Asset:
        for existing in self.assets.values():
            if (existing.domain_id, existing.kind, existing.value) == (
                asset.domain_id,
                asset.kind,
                asset.value,
            ):
                updated = replace(existing, scan_id=asset.scan_id, in_scope=asset.in_scope)
                self.assets[existing.id] = updated
                return updated
        self.assets[asset.id] = asset
        return asset

    async def replace_services(self, asset_id: UUID, services: Sequence[DiscoveredService]) -> None:
        self.services[asset_id] = list(services)

    async def upsert_endpoint(self, asset_id: UUID, probe: HttpProbe) -> None:
        asset = self.assets[asset_id]
        for endpoint in self.endpoints.values():
            if endpoint.asset_id == asset_id and endpoint.url == probe.url:
                self.endpoints[endpoint.id] = replace(
                    endpoint, http_status=probe.http_status, technologies=probe.technologies
                )
                return
        endpoint = Endpoint(
            uuid4(),
            asset_id,
            asset.domain_id,
            probe.url,
            probe.http_status,
            probe.technologies,
            False,
            asset.in_scope,
        )
        self.endpoints[endpoint.id] = endpoint
        if self._endpoint_repo is not None:
            self._endpoint_repo.endpoints.append(endpoint)

    async def list_by_domain(self, domain_id: UUID) -> list[Asset]:
        found = [a for a in self.assets.values() if a.domain_id == domain_id]
        return sorted(found, key=lambda a: (a.kind.value, a.value))

    async def get(self, asset_id: UUID) -> Asset | None:
        return self.assets.get(asset_id)

    async def list_services(self, asset_id: UUID) -> list[DiscoveredService]:
        return list(self.services.get(asset_id, []))

    async def list_endpoints(self, asset_id: UUID) -> list[Endpoint]:
        return [e for e in self.endpoints.values() if e.asset_id == asset_id]

    async def get_endpoint(self, endpoint_id: UUID) -> Endpoint | None:
        return self.endpoints.get(endpoint_id)

    async def set_whitelisted(self, endpoint_id: UUID, whitelisted: bool) -> None:
        self.endpoints[endpoint_id] = replace(self.endpoints[endpoint_id], whitelisted=whitelisted)


class FakeEnumerator:
    def __init__(self) -> None:
        self.hosts: list[str] = []
        self.error: str | None = None
        self.calls: list[str] = []

    async def enumerate(self, domain: str) -> list[str]:
        self.calls.append(domain)
        if self.error:
            raise ToolExecutionError(self.error)
        return list(self.hosts)


class FakeResolver:
    def __init__(self) -> None:
        self.table: dict[str, list[str]] = {}
        self.calls: list[str] = []

    async def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        return list(self.table.get(host, []))


class FakeScanner:
    def __init__(self) -> None:
        self.result: dict[str, list[DiscoveredService]] = {}
        self.error: str | None = None
        self.calls: list[list[str]] = []

    async def scan(self, addresses: Sequence[str]) -> dict[str, list[DiscoveredService]]:
        self.calls.append(list(addresses))
        if self.error:
            raise ToolExecutionError(self.error)
        return dict(self.result)


class FakeProber:
    def __init__(self) -> None:
        self.result: list[HttpProbe] = []
        self.error: str | None = None
        self.calls: list[list[str]] = []

    async def probe(self, hosts: Sequence[str]) -> list[HttpProbe]:
        self.calls.append(list(hosts))
        if self.error:
            raise ToolExecutionError(self.error)
        return list(self.result)


class FakeReconQueue:
    def __init__(self) -> None:
        self.jobs: list[tuple[UUID, str | None]] = []
        self.down = False

    async def enqueue(self, scan_id: UUID, only_host: str | None) -> None:
        if self.down:
            raise QueueUnavailableError
        self.jobs.append((scan_id, only_host))
