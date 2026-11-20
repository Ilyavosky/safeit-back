import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from psycopg_pool import AsyncConnectionPool

from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.recon.run_recon import ReconLimits, RunReconScan
from app.domain.entities.asset import Asset
from app.domain.entities.discovered import DiscoveredService, HttpProbe
from app.domain.entities.scan import Scan
from app.domain.value_objects.asset_kind import AssetKind
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.scan_type import ScanType
from app.infrastructure.db.asset_repository import PostgresAssetRepository
from app.infrastructure.db.audit_repository import PostgresAuditRepository
from app.infrastructure.db.domain_repository import PostgresDomainRepository
from app.infrastructure.db.recon_scan_repository import PostgresReconScanRepository
from app.infrastructure.db.scan_repository import PostgresScanRepository
from tests.fakes import FakeClock
from tests.fakes_recon import FakeEnumerator, FakeProber, FakeResolver, FakeScanner
from tests.pg_seed import World, seed_world

PUBLIC = "93.184.216.34"


def _scan(world: World, created_at: datetime | None = None) -> Scan:
    return Scan(
        uuid4(),
        world.domain.id,
        world.user.id,
        ScanType.RECON,
        JobStatus.QUEUED,
        created_at or datetime.now(UTC),
    )


async def test_only_one_active_recon_scan_per_domain_even_under_concurrency(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    world = await seed_world(migrated_pool)
    repo = PostgresReconScanRepository(migrated_pool)
    results = await asyncio.gather(*(repo.add_if_idle(_scan(world)) for _ in range(8)))
    assert results.count(True) == 1
    async with migrated_pool.connection() as conn:
        cursor = await conn.execute(
            "select count(*) from public.scans where domain_id = %s and type = 'recon' "
            "and status = 'queued'",
            (world.domain.id,),
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] == 1
    other = await seed_world(migrated_pool, domain_name="otro.com", url="https://otro.com/")
    assert await repo.add_if_idle(_scan(other)) is True


async def test_stale_scans_are_failed_and_release_the_domain(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    world = await seed_world(migrated_pool)
    repo = PostgresReconScanRepository(migrated_pool)
    old = _scan(world, datetime.now(UTC) - timedelta(hours=2))
    assert await repo.add_if_idle(old)
    assert await repo.add_if_idle(_scan(world)) is False
    assert await repo.fail_stale(world.domain.id, datetime.now(UTC) - timedelta(hours=1)) == 1
    stored = await PostgresScanRepository(migrated_pool).get(old.id)
    assert stored is not None
    assert stored.status is JobStatus.FAILED
    assert stored.finished_at is not None
    assert await repo.add_if_idle(_scan(world)) is True
    assert await repo.fail_stale(world.domain.id, datetime.now(UTC) - timedelta(hours=1)) == 0


async def test_asset_repository_roundtrip(migrated_pool: AsyncConnectionPool[Any]) -> None:
    world = await seed_world(migrated_pool)
    repo = PostgresAssetRepository(migrated_pool)
    now = datetime.now(UTC)
    host = await repo.upsert(
        Asset(
            uuid4(),
            world.domain.id,
            world.recon_scan.id,
            AssetKind.SUBDOMAIN,
            "api.example.com",
            True,
            now,
        )
    )
    again = await repo.upsert(
        Asset(
            uuid4(),
            world.domain.id,
            world.recon_scan.id,
            AssetKind.SUBDOMAIN,
            "api.example.com",
            True,
            now,
        )
    )
    assert again.id == host.id
    ip = await repo.upsert(
        Asset(uuid4(), world.domain.id, world.recon_scan.id, AssetKind.IP, PUBLIC, True, now)
    )
    assert await repo.get(host.id) == host
    assert await repo.get(uuid4()) is None
    listed = await repo.list_by_domain(world.domain.id)
    assert [(a.kind, a.value) for a in listed] == [
        (AssetKind.IP, PUBLIC),
        (AssetKind.SUBDOMAIN, "api.example.com"),
        (AssetKind.SUBDOMAIN, "example.com"),
    ]

    services = [
        DiscoveredService(443, "tcp", "https", "nginx 1.25", None),
        DiscoveredService(80, "tcp", "http", None, "Ubuntu"),
    ]
    await repo.replace_services(ip.id, services)
    assert [s.port for s in await repo.list_services(ip.id)] == [80, 443]
    await repo.replace_services(ip.id, services[:1])
    assert await repo.list_services(ip.id) == services[:1]

    probe = HttpProbe("api.example.com", "https://api.example.com/", 200, ("Nginx",))
    await repo.upsert_endpoint(host.id, probe)
    await repo.upsert_endpoint(host.id, HttpProbe(probe.host, probe.url, 301, ()))
    endpoints = await repo.list_endpoints(host.id)
    assert [
        (e.url, e.http_status, e.technologies, e.whitelisted, e.in_scope) for e in endpoints
    ] == [("https://api.example.com/", 301, (), False, True)]
    endpoint_id = endpoints[0].id
    await repo.set_whitelisted(endpoint_id, True)
    stored = await repo.get_endpoint(endpoint_id)
    assert stored is not None
    assert stored.whitelisted is True
    assert stored.domain_id == world.domain.id
    await repo.upsert_endpoint(host.id, probe)
    refreshed = await repo.get_endpoint(endpoint_id)
    assert refreshed is not None
    assert refreshed.whitelisted is True
    assert await repo.get_endpoint(uuid4()) is None


async def test_full_recon_against_postgres(migrated_pool: AsyncConnectionPool[Any]) -> None:
    world = await seed_world(migrated_pool)
    clock = FakeClock()
    scans = PostgresScanRepository(migrated_pool)
    assets = PostgresAssetRepository(migrated_pool)
    enumerator, resolver, scanner, prober = (
        FakeEnumerator(),
        FakeResolver(),
        FakeScanner(),
        FakeProber(),
    )
    enumerator.hosts = ["www.example.com", "internal.example.com"]
    resolver.table = {
        "example.com": [PUBLIC],
        "www.example.com": [PUBLIC],
        "internal.example.com": ["10.1.1.1"],
    }
    scanner.result = {PUBLIC: [DiscoveredService(443, "tcp", "https", "nginx", None)]}
    prober.result = [HttpProbe("www.example.com", "https://www.example.com/", 200, ("Nginx",))]
    use_case = RunReconScan(
        domains=PostgresDomainRepository(migrated_pool),
        scans=scans,
        assets=assets,
        enumerator=enumerator,
        resolver=resolver,
        scanner=scanner,
        prober=prober,
        audit=RecordAction(PostgresAuditRepository(migrated_pool)),
        clock=clock,
        limits=ReconLimits(max_assets=50, timeout_seconds=30),
    )
    scan = _scan(world)
    assert await PostgresReconScanRepository(migrated_pool).add_if_idle(scan)
    finished = await use_case.execute(scan.id)
    assert finished is not None
    assert finished.status is JobStatus.DONE
    listed = await assets.list_by_domain(world.domain.id)
    assert {(a.kind, a.value) for a in listed} == {
        (AssetKind.SUBDOMAIN, "example.com"),
        (AssetKind.SUBDOMAIN, "www.example.com"),
        (AssetKind.IP, PUBLIC),
    }
    www = next(a for a in listed if a.value == "www.example.com")
    assert [e.url for e in await assets.list_endpoints(www.id)] == ["https://www.example.com/"]
    async with migrated_pool.connection() as conn:
        cursor = await conn.execute(
            "select detail->>'reason' from public.audit_log where action = 'recon.asset_discarded'"
        )
        rows = await cursor.fetchall()
    assert [row[0] for row in rows] == ["address_not_public"]
