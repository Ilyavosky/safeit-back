from collections.abc import Callable

from fastapi.testclient import TestClient

from tests.conftest import FakeDatabase


def test_health_returns_ok_when_database_is_up(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "up"}


def test_health_returns_503_when_database_is_down(
    make_client: Callable[..., TestClient],
) -> None:
    response = make_client(FakeDatabase(up=False)).get("/health")

    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "database": "down"}


def test_lifespan_opens_and_closes_database(
    make_client: Callable[..., TestClient],
) -> None:
    database = FakeDatabase()

    with make_client(database):
        assert database.opened
        assert not database.closed

    assert database.closed
