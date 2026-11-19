import asyncio
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.recon.assets import GetAsset, ListAssets, SetEndpointWhitelist
from app.application.use_cases.recon.run_recon import ReconLimits, RunReconScan
from app.application.use_cases.recon.start_recon import RescanAsset, StartReconScan
from app.domain.entities.discovered import DiscoveredService, HttpProbe
from app.domain.entities.domain import Domain
from app.domain.entities.scan import Scan
from app.domain.entities.user import User
from app.domain.errors import (
    ConflictError,
    DomainNotVerifiedError,
    EntityNotFoundError,
    OutOfScopeError,
)
from app.domain.errors_queue import QueueUnavailableError
from app.domain.value_objects.asset_kind import AssetKind
from app.domain.value_objects.domain_status import DomainStatus
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.role import Role
from app.domain.value_objects.scan_type import ScanType
from app.domain.value_objects.verification_method import VerificationMethod
from tests.fakes import FakeClock, InMemoryAuditRepository, InMemoryDomainRepository
from tests.fakes_recon import (
    FakeEnumerator,
    FakeProber,
    FakeReconQueue,
    FakeResolver,
    FakeScanner,
    InMemoryAssetRepository,
    InMemoryReconScanRepository,
)
from tests.fakes_testing import InMemoryScanRepository

PUBLIC = "93.184.216.34"
OTHER = "93.184.216.35"


def _user(role: Role = Role.ANALYST) -> User:
    return User(uuid4(), f"{uuid4()}@x.com", "h", role, None, False, FakeClock().now())


class Env:
    def __init__(self, limits: ReconLimits | None = None) -> None:
        self.clock = FakeClock()
        self.owner = _user()
        self.domains = InMemoryDomainRepository()
        self.scans = InMemoryScanRepository()
        self.assets = InMemoryAssetRepository()
        self.audit_repo = InMemoryAuditRepository()
        self.queue = FakeReconQueue()
        self.enumerator = FakeEnumerator()
        self.resolver = FakeResolver()
        self.scanner = FakeScanner()
        self.prober = FakeProber()
        audit = RecordAction(self.audit_repo)
        self.start = StartReconScan(
            self.domains,
            self.scans,
            InMemoryReconScanRepository(self.scans),
            self.queue,
            audit,
            self.clock,
            stale_after_seconds=1800,
        )
        self.run = RunReconScan(
            domains=self.domains,
            scans=self.scans,
            assets=self.assets,
            enumerator=self.enumerator,
            resolver=self.resolver,
            scanner=self.scanner,
            prober=self.prober,
            audit=audit,
            clock=self.clock,
            limits=limits or ReconLimits(max_assets=100, timeout_seconds=5),
        )
        self.rescan = RescanAsset(self.domains, self.assets, self.start)
        self.list_assets = ListAssets(self.domains, self.assets)
        self.get_asset = GetAsset(self.domains, self.assets)
        self.whitelist = SetEndpointWhitelist(self.domains, self.assets, audit)

    async def domain(self, *, verified: bool = True) -> Domain:
        domain = Domain(
            uuid4(),
            self.owner.id,
            "example.com",
            VerificationMethod.DNS_TXT,
            "tok",
            DomainStatus.VERIFIED if verified else DomainStatus.PENDING,
            self.clock.now() if verified else None,
        )
        await self.domains.save(domain)
        return domain

    async def queued(self, domain: Domain) -> Scan:
        scan = await self.start.execute(self.owner, domain.id)
        return scan

    def discard_details(self) -> list[dict[str, object]]:
        return [
            dict(e.detail) for e in self.audit_repo.entries if e.action == "recon.asset_discarded"
        ]

    def finished_detail(self) -> dict[str, object]:
        entries = [e for e in self.audit_repo.entries if e.action == "scan.recon_finished"]
        return dict(entries[-1].detail)


async def test_start_requires_verified_domain_and_enqueues_nothing_otherwise() -> None:
    env = Env()
    pending = await env.domain(verified=False)
    with pytest.raises(DomainNotVerifiedError):
        await env.start.execute(env.owner, pending.id)
    assert env.queue.jobs == []
    assert env.scans.scans == {}
    with pytest.raises(EntityNotFoundError):
        await env.start.execute(_user(), pending.id)


async def test_start_creates_a_queued_scan_and_enqueues_it() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)
    assert (scan.type, scan.status) == (ScanType.RECON, JobStatus.QUEUED)
    assert env.queue.jobs == [(scan.id, None)]
    assert "scan.recon_started" in env.audit_repo.actions()


async def test_only_one_active_recon_per_domain_and_stale_locks_are_released() -> None:
    env = Env()
    domain = await env.domain()
    first = await env.queued(domain)
    with pytest.raises(ConflictError):
        await env.start.execute(env.owner, domain.id)
    assert len(env.queue.jobs) == 1
    env.clock.advance(seconds=1801)
    second = await env.start.execute(env.owner, domain.id)
    assert env.scans.scans[first.id].status is JobStatus.FAILED
    assert second.id != first.id


async def test_queue_outage_fails_the_scan_and_frees_the_domain() -> None:
    env = Env()
    domain = await env.domain()
    env.queue.down = True
    with pytest.raises(QueueUnavailableError):
        await env.start.execute(env.owner, domain.id)
    (scan,) = env.scans.scans.values()
    assert scan.status is JobStatus.FAILED
    assert env.finished_detail()["reason"] == "queue_unavailable"
    env.queue.down = False
    await env.start.execute(env.owner, domain.id)


async def test_full_recon_persists_assets_services_and_endpoints() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)
    env.enumerator.hosts = ["api.example.com", "Example.com"]
    env.resolver.table = {"example.com": [PUBLIC], "api.example.com": [PUBLIC, OTHER]}
    env.scanner.result = {PUBLIC: [DiscoveredService(443, "tcp", "https", "nginx", None)]}
    env.prober.result = [
        HttpProbe("example.com", "https://example.com", 200, ("Nginx",)),
        HttpProbe("api.example.com", "https://api.example.com/", 301, ()),
    ]
    finished = await env.run.execute(scan.id)
    assert finished is not None
    assert finished.status is JobStatus.DONE
    assert finished.started_at is not None
    assert finished.finished_at is not None
    values = {(a.kind, a.value) for a in env.assets.assets.values()}
    assert values == {
        (AssetKind.SUBDOMAIN, "example.com"),
        (AssetKind.SUBDOMAIN, "api.example.com"),
        (AssetKind.IP, PUBLIC),
        (AssetKind.IP, OTHER),
    }
    assert all(a.in_scope for a in env.assets.assets.values())
    assert sorted(env.scanner.calls[0]) == [PUBLIC, OTHER]
    assert sorted(env.prober.calls[0]) == ["api.example.com", "example.com"]
    assert len(env.assets.endpoints) == 2
    assert all(not e.whitelisted for e in env.assets.endpoints.values())
    detail = env.finished_detail()
    assert (detail["status"], detail["assets"], detail["services"], detail["endpoints"]) == (
        "done",
        4,
        1,
        2,
    )


async def test_assets_pointing_to_non_public_addresses_are_discarded_and_audited() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)
    env.enumerator.hosts = ["internal.example.com", "meta.example.com", "gone.example.com"]
    env.resolver.table = {
        "example.com": [PUBLIC],
        "internal.example.com": ["10.0.0.5"],
        "meta.example.com": [PUBLIC, "169.254.169.254"],
    }
    await env.run.execute(scan.id)
    names = {a.value for a in env.assets.assets.values()}
    assert names == {"example.com", PUBLIC}
    assert sorted((d["target"], d["reason"]) for d in env.discard_details()) == [
        ("internal.example.com", "address_not_public"),
        ("meta.example.com", "address_not_public"),
    ]
    assert env.finished_detail()["unresolved"] == 1
    assert "10.0.0.5" not in env.scanner.calls[0]


async def test_hosts_outside_the_domain_never_resolve_or_get_scanned() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)
    env.enumerator.hosts = ["evil.com", "example.com.evil.com", "*.example.com", "-x.example.com"]
    env.resolver.table = {"example.com": [PUBLIC], "evil.com": [PUBLIC]}
    await env.run.execute(scan.id)
    assert env.resolver.calls == ["example.com"]
    assert len(env.discard_details()) == 4
    assert {d["reason"] for d in env.discard_details()} == {"outside_domain"}


async def test_probes_outside_scope_are_discarded() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)
    env.resolver.table = {"example.com": [PUBLIC]}
    env.prober.result = [
        HttpProbe("example.com", "https://example.com/", 200, ()),
        HttpProbe("example.com", "https://evil.com/", 200, ()),
        HttpProbe("other.example.com", "https://other.example.com/", 200, ()),
    ]
    await env.run.execute(scan.id)
    assert [e.url for e in env.assets.endpoints.values()] == ["https://example.com/"]
    assert len(env.discard_details()) == 2


async def test_tool_errors_become_warnings_and_do_not_fail_the_scan() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)
    env.enumerator.error = "subfinder no está instalada"
    env.scanner.error = "nmap no está instalada"
    env.prober.error = "httpx no está instalada"
    env.resolver.table = {"example.com": [PUBLIC]}
    finished = await env.run.execute(scan.id)
    assert finished is not None
    assert finished.status is JobStatus.DONE
    warnings = env.finished_detail()["warnings"]
    assert isinstance(warnings, list)
    assert len(warnings) == 3


async def test_asset_cap_truncates_the_scan() -> None:
    env = Env(ReconLimits(max_assets=3, timeout_seconds=5))
    domain = await env.domain()
    scan = await env.queued(domain)
    env.enumerator.hosts = [f"h{i}.example.com" for i in range(10)]
    env.resolver.table = {h: [PUBLIC] for h in ["example.com", *env.enumerator.hosts]}
    await env.run.execute(scan.id)
    assert len(env.assets.assets) <= 4
    assert env.finished_detail()["truncated"] is True


async def test_timeout_fails_the_scan_and_releases_the_lock() -> None:
    env = Env(ReconLimits(max_assets=10, timeout_seconds=0))

    class Slow(FakeResolver):
        async def resolve(self, host: str) -> list[str]:
            await asyncio.sleep(5)
            return [PUBLIC]

    env.run._resolver = Slow()
    domain = await env.domain()
    scan = await env.queued(domain)
    finished = await env.run.execute(scan.id)
    assert finished is not None
    assert finished.status is JobStatus.FAILED
    assert env.finished_detail()["reason"] == "timeout"
    await env.start.execute(env.owner, domain.id)


async def test_unexpected_errors_and_unverified_domains_fail_the_scan() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)

    class Boom(FakeResolver):
        async def resolve(self, host: str) -> list[str]:
            raise RuntimeError("boom")

    env.run._resolver = Boom()
    finished = await env.run.execute(scan.id)
    assert finished is not None
    assert finished.status is JobStatus.FAILED
    assert env.finished_detail()["reason"] == "error"

    env2 = Env()
    domain2 = await env2.domain()
    scan2 = await env2.queued(domain2)
    env2.domains.domains[domain2.id] = Domain(
        **{**domain2.__dict__, "status": DomainStatus.PENDING}
    )
    finished2 = await env2.run.execute(scan2.id)
    assert finished2 is not None
    assert finished2.status is JobStatus.FAILED
    assert env2.finished_detail()["reason"] == "domain_not_verified"
    assert env2.resolver.calls == []


async def test_run_ignores_unknown_non_queued_and_non_recon_scans() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)
    env.resolver.table = {"example.com": [PUBLIC]}
    assert await env.run.execute(UUID(int=1)) is None
    assert await env.run.execute(scan.id) is not None
    assert await env.run.execute(scan.id) is None
    tests_scan = Scan(
        uuid4(), domain.id, env.owner.id, ScanType.TESTS, JobStatus.QUEUED, env.clock.now()
    )
    await env.scans.add(tests_scan)
    assert await env.run.execute(tests_scan.id) is None


async def test_rescan_targets_a_single_host_and_skips_enumeration() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)
    env.enumerator.hosts = ["api.example.com"]
    env.resolver.table = {"example.com": [PUBLIC], "api.example.com": [PUBLIC]}
    await env.run.execute(scan.id)
    host_asset = next(a for a in env.assets.assets.values() if a.value == "api.example.com")
    ip_asset = next(a for a in env.assets.assets.values() if a.kind is AssetKind.IP)

    rescan = await env.rescan.execute(env.owner, host_asset.id)
    assert env.queue.jobs[-1] == (rescan.id, "api.example.com")
    env.enumerator.calls.clear()
    env.resolver.calls.clear()
    await env.run.execute(rescan.id, "api.example.com")
    assert env.enumerator.calls == []
    assert env.resolver.calls == ["api.example.com"]

    with pytest.raises(ConflictError):
        await env.rescan.execute(env.owner, ip_asset.id)
    with pytest.raises(EntityNotFoundError):
        await env.rescan.execute(env.owner, uuid4())
    with pytest.raises(EntityNotFoundError):
        await env.rescan.execute(_user(), host_asset.id)


async def test_reading_assets_is_private_to_owner_and_admin() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)
    env.resolver.table = {"example.com": [PUBLIC]}
    env.prober.result = [HttpProbe("example.com", "https://example.com/", 200, ("Nginx",))]
    env.scanner.result = {PUBLIC: [DiscoveredService(80, "tcp", "http", None, None)]}
    await env.run.execute(scan.id)
    listed = await env.list_assets.execute(env.owner, domain.id)
    assert [a.value for a in listed] == [PUBLIC, "example.com"]
    host = next(a for a in listed if a.kind is AssetKind.SUBDOMAIN)
    detail = await env.get_asset.execute(_user(Role.ADMIN), host.id)
    assert [e.url for e in detail.endpoints] == ["https://example.com/"]
    ip = next(a for a in listed if a.kind is AssetKind.IP)
    assert [s.port for s in (await env.get_asset.execute(env.owner, ip.id)).services] == [80]
    for reader in (_user(), _user(Role.VIEWER)):
        with pytest.raises(EntityNotFoundError):
            await env.list_assets.execute(reader, domain.id)
        with pytest.raises(EntityNotFoundError):
            await env.get_asset.execute(reader, host.id)
    with pytest.raises(EntityNotFoundError):
        await env.get_asset.execute(env.owner, uuid4())


async def test_whitelist_toggle_is_audited_and_requires_scope_and_access() -> None:
    env = Env()
    domain = await env.domain()
    scan = await env.queued(domain)
    env.resolver.table = {"example.com": [PUBLIC]}
    env.prober.result = [HttpProbe("example.com", "https://example.com/", 200, ())]
    await env.run.execute(scan.id)
    endpoint = next(iter(env.assets.endpoints.values()))
    updated = await env.whitelist.execute(env.owner, endpoint.id, True)
    assert updated.whitelisted is True
    assert env.assets.endpoints[endpoint.id].whitelisted is True
    assert "endpoint.whitelist_changed" in env.audit_repo.actions()
    assert (await env.whitelist.execute(env.owner, endpoint.id, False)).whitelisted is False
    with pytest.raises(EntityNotFoundError):
        await env.whitelist.execute(_user(), endpoint.id, True)
    with pytest.raises(EntityNotFoundError):
        await env.whitelist.execute(env.owner, uuid4(), True)
    env.assets.endpoints[endpoint.id] = type(endpoint)(
        endpoint.id,
        endpoint.asset_id,
        endpoint.domain_id,
        endpoint.url,
        200,
        (),
        False,
        False,
    )
    with pytest.raises(OutOfScopeError):
        await env.whitelist.execute(env.owner, endpoint.id, True)
