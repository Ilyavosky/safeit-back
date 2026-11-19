import base64
import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg_pool import AsyncConnectionPool

os.environ["ENVIRONMENT"] = "dev"
os.environ["DATABASE_URL"] = "postgresql://test:test@localhost:5432/test"
os.environ["JWT_SECRET"] = "t" * 32
os.environ["ENCRYPTION_KEY"] = base64.b64encode(bytes(32)).decode()
os.environ["AUTH_RATE_LIMIT_ATTEMPTS"] = "1000"

from app.config import Settings
from app.container import build_container
from app.domain.entities.allowed_tool import AllowedTool
from app.infrastructure.security.password_hasher import Argon2PasswordHasher
from app.main import create_app
from tests.fakes import (
    FakeClock,
    FakeDatabase,
    FakeDomainVerifier,
    InMemoryAuditRepository,
    InMemoryDomainRepository,
    InMemoryRefreshTokenRepository,
    InMemoryUserRepository,
)
from tests.fakes_cve import FakeEpss, FakeKev, FakeNvd, InMemoryCveRepository
from tests.fakes_recon import (
    FakeEnumerator,
    FakeProber,
    FakeReconQueue,
    FakeResolver,
    FakeScanner,
    InMemoryAssetRepository,
    InMemoryReconScanRepository,
)
from tests.fakes_testing import (
    FakeRegistry,
    FakeRunner,
    ImmediateScheduler,
    InMemoryEndpointRepository,
    InMemoryFindingRepository,
    InMemoryScanRepository,
    InMemoryTestRunRepository,
    InMemoryToolRepository,
)


@pytest.fixture
def settings() -> Settings:
    return Settings()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def users_repo() -> InMemoryUserRepository:
    return InMemoryUserRepository()


@pytest.fixture
def refresh_repo() -> InMemoryRefreshTokenRepository:
    return InMemoryRefreshTokenRepository()


@pytest.fixture
def domains_repo() -> InMemoryDomainRepository:
    return InMemoryDomainRepository()


@pytest.fixture
def audit_repo() -> InMemoryAuditRepository:
    return InMemoryAuditRepository()


@pytest.fixture
def domain_verifier() -> FakeDomainVerifier:
    return FakeDomainVerifier()


@pytest.fixture
def cve_repo() -> InMemoryCveRepository:
    return InMemoryCveRepository()


@pytest.fixture
def nvd() -> FakeNvd:
    return FakeNvd()


@pytest.fixture
def scans_repo() -> InMemoryScanRepository:
    return InMemoryScanRepository()


@pytest.fixture
def endpoints_repo() -> InMemoryEndpointRepository:
    return InMemoryEndpointRepository()


@pytest.fixture
def test_runs_repo() -> InMemoryTestRunRepository:
    return InMemoryTestRunRepository()


@pytest.fixture
def assets_repo(endpoints_repo: InMemoryEndpointRepository) -> InMemoryAssetRepository:
    return InMemoryAssetRepository(endpoints_repo)


@pytest.fixture
def recon_queue() -> FakeReconQueue:
    return FakeReconQueue()


@pytest.fixture
def enumerator() -> FakeEnumerator:
    return FakeEnumerator()


@pytest.fixture
def resolver() -> FakeResolver:
    return FakeResolver()


@pytest.fixture
def port_scanner() -> FakeScanner:
    return FakeScanner()


@pytest.fixture
def prober() -> FakeProber:
    return FakeProber()


@pytest.fixture
def tools_repo() -> InMemoryToolRepository:
    policy = {
        "tags_allowlist": ["cve", "misconfig", "exposure", "tech"],
        "tags_denylist": ["dos", "intrusive", "fuzz", "bruteforce"],
        "rate_limit": 50,
        "timeout_s": 600,
    }
    return InMemoryToolRepository(
        [
            AllowedTool(uuid4(), "headers", {"timeout_s": 30}, True),
            AllowedTool(uuid4(), "testssl", {"timeout_s": 300}, True),
            AllowedTool(uuid4(), "nuclei", policy, True),
        ]
    )


@pytest.fixture
def scheduler() -> ImmediateScheduler:
    return ImmediateScheduler()


@pytest.fixture
def runners() -> dict[str, FakeRunner]:
    return {name: FakeRunner() for name in ("headers", "testssl", "nuclei")}


@pytest.fixture
def make_client(
    settings: Settings,
    clock: FakeClock,
    users_repo: InMemoryUserRepository,
    refresh_repo: InMemoryRefreshTokenRepository,
    domains_repo: InMemoryDomainRepository,
    audit_repo: InMemoryAuditRepository,
    domain_verifier: FakeDomainVerifier,
    cve_repo: InMemoryCveRepository,
    nvd: FakeNvd,
    scans_repo: InMemoryScanRepository,
    endpoints_repo: InMemoryEndpointRepository,
    tools_repo: InMemoryToolRepository,
    test_runs_repo: InMemoryTestRunRepository,
    scheduler: ImmediateScheduler,
    runners: dict[str, FakeRunner],
    assets_repo: InMemoryAssetRepository,
    recon_queue: FakeReconQueue,
    enumerator: FakeEnumerator,
    resolver: FakeResolver,
    port_scanner: FakeScanner,
    prober: FakeProber,
) -> Callable[..., TestClient]:
    def factory(
        database: FakeDatabase | None = None,
        custom_settings: Settings | None = None,
    ) -> TestClient:
        container = build_container(
            custom_settings or settings,
            database=database or FakeDatabase(),
            users=users_repo,
            refresh_tokens=refresh_repo,
            domains=domains_repo,
            audit=audit_repo,
            domain_verifier=domain_verifier,
            hasher=Argon2PasswordHasher(time_cost=1, memory_cost=8, parallelism=1),
            clock=clock,
            cve_repository=cve_repo,
            nvd=nvd,
            epss=FakeEpss(),
            kev=FakeKev(),
            scans=scans_repo,
            endpoints=endpoints_repo,
            tools=tools_repo,
            test_runs=test_runs_repo,
            findings=InMemoryFindingRepository(test_runs_repo),
            tool_registry=FakeRegistry(runners),
            scheduler=scheduler,
            assets=assets_repo,
            recon_scans=InMemoryReconScanRepository(scans_repo),
            recon_queue=recon_queue,
            enumerator=enumerator,
            resolver=resolver,
            port_scanner=port_scanner,
            prober=prober,
        )
        return TestClient(create_app(container), raise_server_exceptions=False)

    return factory


@pytest.fixture
def client(make_client: Callable[..., TestClient]) -> TestClient:
    return make_client()


MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "bd" / "supabase" / "migrations"
SCHEMA_MIGRATIONS = (
    "01_safeit_auth.sql",
    "02_safeit_scope.sql",
    "03_safeit_ai_findings.sql",
    "04_safeit_audit_log.sql",
    "05_safeit_guards.sql",
    "06_safeit_indexes.sql",
)


@pytest.fixture
async def migrated_pool() -> AsyncIterator[AsyncConnectionPool[Any]]:
    dsn = os.environ.get("TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("TEST_DATABASE_URL no está definida")
    scripts = [MIGRATIONS_DIR / name for name in SCHEMA_MIGRATIONS]
    if not all(script.exists() for script in scripts):
        pytest.skip("No se encontraron las migraciones de bd/supabase/migrations")
    pool: AsyncConnectionPool[Any] = AsyncConnectionPool(
        dsn, min_size=1, max_size=8, open=False, kwargs={"autocommit": True}
    )
    await pool.open(wait=True)
    created = False
    try:
        async with pool.connection() as conn:
            cursor = await conn.execute("select to_regclass('public.users')")
            row = await cursor.fetchone()
            if row is not None and row[0] is not None:
                pytest.skip("public.users ya existe; usa una base vacía para estas pruebas")
            for script in scripts:
                await conn.execute(script.read_text(encoding="utf-8"))
            created = True
        yield pool
    finally:
        if created:
            async with pool.connection() as conn:
                await conn.execute("drop schema public cascade")
                await conn.execute("create schema public")
        await pool.close()
