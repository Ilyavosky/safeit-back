from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.domain import errors

CASES: list[tuple[errors.DomainError, int, str]] = [
    (errors.EntityNotFoundError("domain", 1), 404, "not_found"),
    (errors.ConflictError(), 409, "conflict"),
    (errors.DomainAlreadyClaimedError(), 409, "domain_already_claimed"),
    (errors.InvalidCredentialsError(), 401, "invalid_credentials"),
    (errors.MfaRequiredError(), 401, "mfa_required"),
    (errors.InvalidMfaCodeError(), 401, "invalid_mfa_code"),
    (errors.InvalidTokenError(), 401, "invalid_token"),
    (errors.TokenReuseDetectedError(), 401, "token_reuse_detected"),
    (errors.PermissionDeniedError(), 403, "permission_denied"),
    (errors.InvalidDomainNameError(), 422, "invalid_domain_name"),
    (errors.DomainNotVerifiedError(), 422, "domain_not_verified"),
    (errors.DomainVerificationFailedError(), 422, "domain_verification_failed"),
    (errors.OutOfScopeError(), 403, "out_of_scope"),
    (errors.EndpointNotWhitelistedError(), 403, "endpoint_not_whitelisted"),
    (errors.ToolNotAllowedError("bash"), 403, "tool_not_allowed"),
    (errors.LlmOutputRejectedError(), 422, "llm_output_rejected"),
    (errors.WeakPasswordError(), 422, "weak_password"),
    (errors.RateLimitExceededError(), 429, "rate_limited"),
    (errors.DomainError(), 400, "domain_error"),
]


def _client_raising(make_client: Callable[..., TestClient], exc: Exception) -> TestClient:
    client = make_client()
    app: FastAPI = client.app  # type: ignore[assignment]

    @app.get("/_raise")
    async def _raise() -> None:
        raise exc

    return client


@pytest.mark.parametrize(("exc", "status", "code"), CASES, ids=[c[2] for c in CASES])
def test_domain_errors_map_to_status_and_code(
    make_client: Callable[..., TestClient],
    exc: errors.DomainError,
    status: int,
    code: str,
) -> None:
    response = _client_raising(make_client, exc).get("/_raise")

    assert response.status_code == status
    body = response.json()
    assert body["code"] == code
    assert body["message"] == exc.message
    assert body["request_id"] == response.headers["X-Request-ID"]


def test_validation_error_has_details(client: TestClient) -> None:
    app: FastAPI = client.app  # type: ignore[assignment]

    @app.get("/_items/{item_id}")
    async def _item(item_id: int) -> dict[str, int]:
        return {"item_id": item_id}

    response = client.get("/_items/not-a-number")

    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "validation_error"
    assert body["details"][0]["loc"] == ["path", "item_id"]


def test_unknown_route_uses_error_format(client: TestClient) -> None:
    response = client.get("/does-not-exist")

    assert response.status_code == 404
    assert response.json()["code"] == "not_found"
    assert response.json()["request_id"]


def test_unhandled_error_does_not_leak_details(
    make_client: Callable[..., TestClient],
) -> None:
    response = _client_raising(make_client, RuntimeError("password=hunter2")).get("/_raise")

    assert response.status_code == 500
    body = response.json()
    assert body["code"] == "internal_error"
    assert "hunter2" not in response.text
