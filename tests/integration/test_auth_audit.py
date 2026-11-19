from fastapi.testclient import TestClient

from tests.fakes import InMemoryAuditRepository, InMemoryUserRepository
from tests.helpers import EMAIL, PASSWORD, bearer, login, refresh_with, register, register_and_login


def test_register_and_login_are_audited(
    client: TestClient, audit_repo: InMemoryAuditRepository, users_repo: InMemoryUserRepository
) -> None:
    register_and_login(client)
    user = users_repo.by_email(EMAIL)
    assert audit_repo.actions() == ["auth.register", "auth.login"]
    assert all(e.user_id == user.id for e in audit_repo.entries)
    assert audit_repo.entries[1].detail["mfa"] is False


def test_failed_logins_are_audited_without_leaking_the_email(
    client: TestClient, audit_repo: InMemoryAuditRepository
) -> None:
    register(client)
    login(client, password="wrong-password-123")
    login(client, email="ghost@example.com")
    failures = [e for e in audit_repo.entries if e.action == "auth.login_failed"]
    assert len(failures) == 2
    assert failures[0].user_id is not None
    assert failures[1].user_id is None
    assert all("email" not in e.detail and "password" not in e.detail for e in audit_repo.entries)


def test_token_reuse_is_audited(client: TestClient, audit_repo: InMemoryAuditRepository) -> None:
    register_and_login(client)
    first = client.cookies.get("safeit_refresh")
    assert refresh_with(client, first).status_code == 200
    assert refresh_with(client, first).status_code == 401
    assert "auth.token_reuse_detected" in audit_repo.actions()


def test_logout_and_profile_changes_are_audited(
    client: TestClient, audit_repo: InMemoryAuditRepository
) -> None:
    response = register_and_login(client)
    patch = client.patch(
        "/users/me",
        json={"current_password": PASSWORD, "new_password": "another-long-password-1"},
        headers=bearer(response),
    )
    assert patch.status_code == 200
    client.post("/auth/logout")
    updated = next(e for e in audit_repo.entries if e.action == "auth.profile_updated")
    assert updated.detail == {"email_changed": False, "password_changed": True}
