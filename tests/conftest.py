import base64
import os
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

os.environ["ENVIRONMENT"] = "dev"
os.environ["DATABASE_URL"] = "postgresql://test:test@localhost:5432/test"
os.environ["JWT_SECRET"] = "t" * 32
os.environ["ENCRYPTION_KEY"] = base64.b64encode(bytes(32)).decode()

from app.config import Settings
from app.container import Container
from app.main import create_app


class FakeDatabase:
    def __init__(self, up: bool = True) -> None:
        self.up = up
        self.opened = False
        self.closed = False

    async def open(self) -> None:
        self.opened = True

    async def close(self) -> None:
        self.closed = True

    async def ping(self) -> bool:
        return self.up


@pytest.fixture
def settings() -> Settings:
    return Settings()


@pytest.fixture
def make_client(settings: Settings) -> Callable[..., TestClient]:
    def factory(database: FakeDatabase | None = None) -> TestClient:
        container = Container(settings=settings, database=database or FakeDatabase())
        return TestClient(create_app(container), raise_server_exceptions=False)

    return factory


@pytest.fixture
def client(make_client: Callable[..., TestClient]) -> TestClient:
    return make_client()
