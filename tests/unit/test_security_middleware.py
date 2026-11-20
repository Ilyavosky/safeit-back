from collections.abc import Callable

from fastapi.testclient import TestClient

from app.config import Settings


def test_security_headers_present(client: TestClient) -> None:
    response = client.get("/health")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "Strict-Transport-Security" not in response.headers


def test_auth_responses_are_not_cached(client: TestClient) -> None:
    response = client.post("/auth/login", json={"email": "a@b.co", "password": "x"})

    assert response.headers["Cache-Control"] == "no-store"


def test_declared_oversized_body_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/auth/login",
        content=b"x" * 2_000_000,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["code"] == "payload_too_large"


def test_docs_and_openapi_disabled_in_prod(make_client: Callable[..., TestClient]) -> None:
    prod_client = make_client(
        custom_settings=Settings(environment="prod", redis_url="redis://localhost:6379/0")
    )

    assert prod_client.get("/docs").status_code == 404
    assert prod_client.get("/openapi.json").status_code == 404
    assert "Strict-Transport-Security" in prod_client.get("/health").headers
