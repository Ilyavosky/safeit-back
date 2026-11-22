import re
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from tests.fakes import (
    FakeClock,
    FakeMailer,
    InMemoryAuditRepository,
    InMemoryPasswordResetTokenRepository,
    InMemoryRefreshTokenRepository,
)
from tests.helpers import EMAIL, PASSWORD, login, refresh_with, register

NEW_PASSWORD = "another-strong-passphrase"
FORGOT = "/auth/password/forgot"
RESET = "/auth/password/reset"


def _token_from(mailer: FakeMailer) -> str:
    link = re.search(r"https?://\S+", mailer.sent[-1].text)
    assert link is not None
    return parse_qs(urlsplit(link.group(0)).query)["token"][0]


def test_forgot_sends_email_with_reset_link(client: TestClient, mailer: FakeMailer) -> None:
    register(client)

    response = client.post(FORGOT, json={"email": EMAIL})

    assert response.status_code == 202
    assert len(mailer.sent) == 1
    message = mailer.sent[0]
    assert message.to == EMAIL
    assert "/reset-password?token=" in message.text
    assert "/reset-password?token=" in message.html


def test_forgot_answers_the_same_for_unknown_email(client: TestClient, mailer: FakeMailer) -> None:
    register(client)

    known = client.post(FORGOT, json={"email": EMAIL})
    unknown = client.post(FORGOT, json={"email": "nadie@example.com"})

    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
    assert len(mailer.sent) == 1


def test_forgot_survives_mail_provider_failure(client: TestClient, mailer: FakeMailer) -> None:
    register(client)
    mailer.fail = True

    response = client.post(FORGOT, json={"email": EMAIL})

    assert response.status_code == 202


def test_reset_changes_password_and_revokes_sessions(
    client: TestClient, mailer: FakeMailer, refresh_repo: InMemoryRefreshTokenRepository
) -> None:
    register(client)
    session = login(client)
    refresh_cookie = session.cookies.get("safeit_refresh")
    assert refresh_cookie
    client.post(FORGOT, json={"email": EMAIL})

    response = client.post(RESET, json={"token": _token_from(mailer), "new_password": NEW_PASSWORD})

    assert response.status_code == 204
    assert login(client, password=PASSWORD).status_code == 401
    assert login(client, password=NEW_PASSWORD).status_code == 200
    assert refresh_with(client, refresh_cookie).status_code == 401


def test_reset_token_is_single_use(client: TestClient, mailer: FakeMailer) -> None:
    register(client)
    client.post(FORGOT, json={"email": EMAIL})
    token = _token_from(mailer)

    first = client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})
    second = client.post(RESET, json={"token": token, "new_password": "yet-another-passphrase"})

    assert first.status_code == 204
    assert second.status_code == 400
    assert second.json()["code"] == "invalid_reset_token"


def test_reset_token_expires(client: TestClient, mailer: FakeMailer, clock: FakeClock) -> None:
    register(client)
    client.post(FORGOT, json={"email": EMAIL})
    token = _token_from(mailer)

    clock.advance(minutes=31)
    response = client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_reset_token"


def test_new_request_invalidates_previous_token(client: TestClient, mailer: FakeMailer) -> None:
    register(client)
    client.post(FORGOT, json={"email": EMAIL})
    old = _token_from(mailer)
    client.post(FORGOT, json={"email": EMAIL})
    new = _token_from(mailer)

    stale = client.post(RESET, json={"token": old, "new_password": NEW_PASSWORD})
    fresh = client.post(RESET, json={"token": new, "new_password": NEW_PASSWORD})

    assert stale.status_code == 400
    assert fresh.status_code == 204


def test_weak_password_does_not_burn_the_token(client: TestClient, mailer: FakeMailer) -> None:
    register(client)
    client.post(FORGOT, json={"email": EMAIL})
    token = _token_from(mailer)

    weak = client.post(RESET, json={"token": token, "new_password": "short"})
    ok = client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})

    assert weak.status_code == 422
    assert ok.status_code == 204


def test_invalid_token_is_rejected(client: TestClient) -> None:
    response = client.post(RESET, json={"token": "x" * 40, "new_password": NEW_PASSWORD})

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_reset_token"


def test_tokens_are_stored_hashed_and_actions_audited(
    client: TestClient,
    mailer: FakeMailer,
    reset_repo: InMemoryPasswordResetTokenRepository,
    audit_repo: InMemoryAuditRepository,
) -> None:
    register(client)
    client.post(FORGOT, json={"email": EMAIL})
    token = _token_from(mailer)
    client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})

    assert all(token not in stored.token_hash for stored in reset_repo.tokens.values())
    actions = {entry.action for entry in audit_repo.entries}
    assert {"auth.password_reset_requested", "auth.password_reset_completed"} <= actions
    assert all(token not in str(entry.detail) for entry in audit_repo.entries)
