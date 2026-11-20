import pyotp
from fastapi.testclient import TestClient

from app.config import Settings
from tests.fakes import FakeClock, InMemoryRefreshTokenRepository, InMemoryUserRepository
from tests.helpers import (
    EMAIL,
    PASSWORD,
    bearer,
    login,
    refresh_with,
    register,
    register_and_login,
)


def test_register_login_and_read_profile(client: TestClient) -> None:
    created = register(client)

    assert created.status_code == 201
    body = created.json()
    assert body["email"] == EMAIL
    assert body["role"] == "viewer"
    assert body["mfa_enabled"] is False
    assert "password" not in created.text

    response = login(client)
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["mfa_required"] is False

    me = client.get("/users/me", headers=bearer(response))
    assert me.status_code == 200
    assert me.json()["email"] == EMAIL


def test_login_sets_httponly_strict_refresh_cookie(client: TestClient) -> None:
    register(client)
    response = login(client)

    header = response.headers["set-cookie"].lower()
    assert "safeit_refresh=" in header
    assert "httponly" in header
    assert "samesite=strict" in header
    assert "path=/auth" in header


def test_duplicate_email_is_rejected_ignoring_case(client: TestClient) -> None:
    assert register(client).status_code == 201

    duplicate = register(client, email="ANA@Example.com")

    assert duplicate.status_code == 409
    assert duplicate.json()["code"] == "conflict"


def test_weak_password_is_rejected(client: TestClient) -> None:
    response = register(client, password="corta")

    assert response.status_code == 422
    assert response.json()["code"] == "weak_password"


def test_wrong_password_and_unknown_email_look_the_same(client: TestClient) -> None:
    register(client)

    wrong_password = login(client, password="otra-clave-distinta")
    unknown_email = login(client, email="nadie@example.com")

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json()["code"] == unknown_email.json()["code"] == "invalid_credentials"
    assert wrong_password.json()["message"] == unknown_email.json()["message"]


def test_refresh_rotates_the_token(client: TestClient) -> None:
    first = register_and_login(client)
    old_raw = first.cookies.get("safeit_refresh")

    refreshed = refresh_with(client, old_raw)

    assert refreshed.status_code == 200
    new_raw = refreshed.cookies.get("safeit_refresh")
    assert new_raw
    assert new_raw != old_raw
    me = client.get("/users/me", headers=bearer(refreshed))
    assert me.status_code == 200


def test_reusing_a_rotated_token_revokes_the_whole_family(
    client: TestClient, refresh_repo: InMemoryRefreshTokenRepository
) -> None:
    first = register_and_login(client)
    old_raw = first.cookies.get("safeit_refresh")
    refreshed = refresh_with(client, old_raw)
    newest_raw = refreshed.cookies.get("safeit_refresh")

    replay = refresh_with(client, old_raw)

    assert replay.status_code == 401
    assert replay.json()["code"] == "token_reuse_detected"
    assert refresh_repo.active_count() == 0
    after = refresh_with(client, newest_raw)
    assert after.status_code == 401
    assert after.json()["code"] == "invalid_token"


def test_refresh_without_cookie_is_rejected(client: TestClient) -> None:
    response = refresh_with(client, None)

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_expired_refresh_token_is_rejected(client: TestClient, clock: FakeClock) -> None:
    first = register_and_login(client)
    clock.advance(days=8)

    response = refresh_with(client, first.cookies.get("safeit_refresh"))

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_logout_revokes_the_session(client: TestClient) -> None:
    first = register_and_login(client)
    raw = first.cookies.get("safeit_refresh")

    logout = client.post("/auth/logout", headers={"Cookie": f"safeit_refresh={raw}"})

    assert logout.status_code == 204
    after = refresh_with(client, raw)
    assert after.status_code == 401
    assert after.json()["code"] == "invalid_token"


def test_logout_without_session_is_a_no_op(client: TestClient) -> None:
    assert client.post("/auth/logout").status_code == 204


def _enable_mfa(client: TestClient, session: dict[str, str]) -> str:
    setup = client.post("/auth/mfa/setup", headers=session)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert setup.json()["otpauth_uri"].startswith("otpauth://totp/")
    enable = client.post(
        "/auth/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=session
    )
    assert enable.status_code == 204
    return str(secret)


def test_mfa_setup_login_and_verify(client: TestClient) -> None:
    first = register_and_login(client)
    secret = _enable_mfa(client, bearer(first))

    challenge = login(client)

    assert challenge.status_code == 200
    assert challenge.json()["mfa_required"] is True
    assert "access_token" not in challenge.json()
    assert "safeit_refresh" not in challenge.headers.get("set-cookie", "")

    verified = client.post(
        "/auth/mfa/verify",
        json={"mfa_token": challenge.json()["mfa_token"], "code": pyotp.TOTP(secret).now()},
    )
    assert verified.status_code == 200
    assert verified.cookies.get("safeit_refresh")
    assert client.get("/users/me", headers=bearer(verified)).json()["mfa_enabled"] is True


def test_mfa_verify_rejects_wrong_code(client: TestClient) -> None:
    first = register_and_login(client)
    _enable_mfa(client, bearer(first))
    challenge = login(client)

    response = client.post(
        "/auth/mfa/verify",
        json={"mfa_token": challenge.json()["mfa_token"], "code": "000000"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_mfa_code"


def test_mfa_verify_rejects_an_access_token_as_challenge(client: TestClient) -> None:
    first = register_and_login(client)
    secret = _enable_mfa(client, bearer(first))

    response = client.post(
        "/auth/mfa/verify",
        json={"mfa_token": first.json()["access_token"], "code": pyotp.TOTP(secret).now()},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


def test_mfa_cannot_be_set_up_twice_or_enabled_without_setup(client: TestClient) -> None:
    first = register_and_login(client)
    session = bearer(first)

    early = client.post("/auth/mfa/enable", json={"code": "123456"}, headers=session)
    assert early.status_code == 409

    _enable_mfa(client, session)
    again = client.post("/auth/mfa/setup", headers=session)
    assert again.status_code == 409


def test_mfa_secret_is_stored_encrypted(
    client: TestClient, users_repo: InMemoryUserRepository
) -> None:
    first = register_and_login(client)
    secret = _enable_mfa(client, bearer(first))

    stored = users_repo.by_email(EMAIL).totp_secret_enc

    assert stored is not None
    assert secret not in stored
    assert stored.startswith("v1:")


def test_login_is_rate_limited(make_client, settings: Settings) -> None:  # type: ignore[no-untyped-def]
    limited = make_client(
        custom_settings=settings.model_copy(update={"auth_rate_limit_attempts": 3})
    )
    register(limited)

    statuses = [login(limited, password="incorrecta-12345").status_code for _ in range(3)]
    blocked = login(limited)

    assert statuses == [401, 401, 401]
    assert blocked.status_code == 429
    assert blocked.json()["code"] == "rate_limited"


def test_change_password_revokes_sessions(client: TestClient) -> None:
    first = register_and_login(client)
    raw = first.cookies.get("safeit_refresh")
    new_password = "una-clave-totalmente-nueva"

    updated = client.patch(
        "/users/me",
        json={"current_password": PASSWORD, "new_password": new_password},
        headers=bearer(first),
    )

    assert updated.status_code == 200
    assert login(client).status_code == 401
    assert login(client, password=new_password).status_code == 200
    assert refresh_with(client, raw).status_code == 401


def test_profile_update_requires_current_password(client: TestClient) -> None:
    first = register_and_login(client)

    response = client.patch(
        "/users/me",
        json={"current_password": "no-es-la-clave", "email": "otra@example.com"},
        headers=bearer(first),
    )

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"


def test_change_email_and_conflict(client: TestClient) -> None:
    register(client, email="otro@example.com")
    first = register_and_login(client)

    taken = client.patch(
        "/users/me",
        json={"current_password": PASSWORD, "email": "otro@example.com"},
        headers=bearer(first),
    )
    assert taken.status_code == 409

    changed = client.patch(
        "/users/me",
        json={"current_password": PASSWORD, "email": "Nueva@Example.com"},
        headers=bearer(first),
    )
    assert changed.status_code == 200
    assert changed.json()["email"] == "nueva@example.com"


def test_cors_preflight_allows_put_from_configured_origin(client: TestClient) -> None:
    response = client.options(
        "/endpoints/00000000-0000-0000-0000-000000000000/whitelist",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert response.status_code == 200
    assert "PUT" in response.headers["access-control-allow-methods"]
