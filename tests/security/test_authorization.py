import base64
import json
from datetime import timedelta
from uuid import uuid4

import jwt
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.container import Container
from app.domain.value_objects.role import Role
from app.interfaces.api.dependencies import require_role
from tests.fakes import FakeClock, InMemoryUserRepository
from tests.helpers import EMAIL, bearer, register_and_login


def _b64(data: dict[str, object]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture
def guarded_client(client: TestClient) -> TestClient:
    app: FastAPI = client.app  # type: ignore[assignment]

    analysts_only = Depends(require_role(Role.ADMIN, Role.ANALYST))

    @app.get("/_analysts", dependencies=[analysts_only])
    async def _analysts() -> dict[str, str]:
        return {"ok": "yes"}

    return client


def test_protected_route_requires_a_token(client: TestClient) -> None:
    response = client.get("/users/me")

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


@pytest.mark.parametrize("header", ["Bearer", "Bearer basura", "Basic abc", "abc"])
def test_malformed_authorization_header_is_rejected(client: TestClient, header: str) -> None:
    response = client.get("/users/me", headers={"Authorization": header})

    assert response.status_code == 401


def test_tampered_token_is_rejected(client: TestClient) -> None:
    session = register_and_login(client)
    token = session.json()["access_token"]
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")

    response = client.get("/users/me", headers={"Authorization": f"Bearer {tampered}"})

    assert response.status_code == 401


def test_token_with_alg_none_is_rejected(
    client: TestClient, users_repo: InMemoryUserRepository
) -> None:
    register_and_login(client)
    user = users_repo.by_email(EMAIL)
    header = _b64({"alg": "none", "typ": "JWT"})
    payload = _b64(
        {
            "iss": "safeit",
            "sub": str(user.id),
            "typ": "access",
            "role": "admin",
            "iat": 1,
            "exp": 4_102_444_800,
        }
    )

    response = client.get("/users/me", headers={"Authorization": f"Bearer {header}.{payload}."})

    assert response.status_code == 401


def test_token_signed_with_another_secret_is_rejected(
    client: TestClient, users_repo: InMemoryUserRepository, clock: FakeClock
) -> None:
    register_and_login(client)
    user = users_repo.by_email(EMAIL)
    forged = jwt.encode(
        {
            "iss": "safeit",
            "sub": str(user.id),
            "typ": "access",
            "role": "admin",
            "iat": int(clock.now().timestamp()),
            "exp": int((clock.now() + timedelta(minutes=5)).timestamp()),
        },
        "x" * 32,
        algorithm="HS256",
    )

    response = client.get("/users/me", headers={"Authorization": f"Bearer {forged}"})

    assert response.status_code == 401


def test_expired_access_token_is_rejected(client: TestClient, clock: FakeClock) -> None:
    session = register_and_login(client)
    clock.advance(minutes=16)

    response = client.get("/users/me", headers=bearer(session))

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_token_of_a_deleted_user_is_rejected(
    client: TestClient, users_repo: InMemoryUserRepository
) -> None:
    session = register_and_login(client)
    users_repo.delete(EMAIL)

    response = client.get("/users/me", headers=bearer(session))

    assert response.status_code == 401


def test_viewer_cannot_use_analyst_routes(guarded_client: TestClient) -> None:
    session = register_and_login(guarded_client)

    response = guarded_client.get("/_analysts", headers=bearer(session))

    assert response.status_code == 403
    assert response.json()["code"] == "permission_denied"


def test_role_is_read_from_the_database_on_every_request(
    guarded_client: TestClient, users_repo: InMemoryUserRepository
) -> None:
    session = register_and_login(guarded_client)
    headers = bearer(session)

    users_repo.set_role(EMAIL, Role.ANALYST)
    assert guarded_client.get("/_analysts", headers=headers).status_code == 200

    users_repo.set_role(EMAIL, Role.VIEWER)
    assert guarded_client.get("/_analysts", headers=headers).status_code == 403


def test_unknown_user_id_in_a_valid_token_is_rejected(client: TestClient, clock: FakeClock) -> None:
    container: Container = client.app.state.container  # type: ignore[attr-defined]
    token = container.tokens.issue_access_token(uuid4(), Role.ADMIN).token

    response = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
