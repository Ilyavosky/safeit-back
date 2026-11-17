import base64
import os
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

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
def make_client(
    settings: Settings,
    clock: FakeClock,
    users_repo: InMemoryUserRepository,
    refresh_repo: InMemoryRefreshTokenRepository,
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
            hasher=Argon2PasswordHasher(time_cost=1, memory_cost=8, parallelism=1),
            clock=clock,
        )
        return TestClient(create_app(container), raise_server_exceptions=False)

    return factory


@pytest.fixture
def client(make_client: Callable[..., TestClient]) -> TestClient:
    return make_client()
