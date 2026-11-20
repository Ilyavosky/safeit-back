import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

PUBLIC = {
    ("GET", "/health"),
    ("POST", "/auth/register"),
    ("POST", "/auth/login"),
    ("POST", "/auth/mfa/verify"),
    ("POST", "/auth/refresh"),
    ("POST", "/auth/logout"),
}


def _protected_routes(app: FastAPI) -> list[tuple[str, str]]:
    routes: list[tuple[str, str]] = []
    for path, operations in app.openapi()["paths"].items():
        for method in operations:
            if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            if (method.upper(), path) not in PUBLIC:
                routes.append((method.upper(), path))
    return routes


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "00000000-0000-0000-0000-000000000000", path)


def test_every_non_public_route_requires_authentication(client: TestClient) -> None:
    app: FastAPI = client.app  # type: ignore[assignment]
    routes = _protected_routes(app)

    assert routes
    for method, path in routes:
        response = client.request(method, _concrete(path))
        assert response.status_code == 401, f"{method} {path} respondió {response.status_code}"


@pytest.mark.parametrize("path", ["/auth/refresh", "/auth/logout"])
def test_refresh_endpoints_without_cookie_do_not_issue_tokens(
    client: TestClient, path: str
) -> None:
    response = client.post(path)

    assert "access_token" not in response.text
    assert response.status_code in {200, 204, 401}
