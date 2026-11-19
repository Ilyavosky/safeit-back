import base64
import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

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
def make_client(
    settings: Settings,
    clock: FakeClock,
    users_repo: InMemoryUserRepository,
    refresh_repo: InMemoryRefreshTokenRepository,
    domains_repo: InMemoryDomainRepository,
    audit_repo: InMemoryAuditRepository,
    domain_verifier: FakeDomainVerifier,
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
