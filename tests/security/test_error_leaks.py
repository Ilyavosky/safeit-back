from fastapi.testclient import TestClient

from tests.helpers import EMAIL, PASSWORD, register_and_login


def test_unknown_route_does_not_leak_internals(client: TestClient) -> None:
    response = client.get("/no-existe")

    assert response.status_code == 404
    body = response.text.lower()
    assert "traceback" not in body
    assert "site-packages" not in body


def test_login_errors_do_not_reveal_whether_the_email_exists(client: TestClient) -> None:
    register_and_login(client)

    wrong_password = client.post(
        "/auth/login", json={"email": EMAIL, "password": "otra-clave-larga-1"}
    )
    unknown_email = client.post(
        "/auth/login", json={"email": "nadie@example.com", "password": PASSWORD}
    )

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json()["code"] == unknown_email.json()["code"]
    assert wrong_password.json()["message"] == unknown_email.json()["message"]


def test_validation_errors_do_not_echo_the_submitted_password(client: TestClient) -> None:
    secret = "clave-secreta-que-no-debe-aparecer"

    response = client.post("/auth/register", json={"email": "no-es-correo", "password": secret})

    assert response.status_code == 422
    assert secret not in response.text


def test_error_responses_carry_a_request_id(client: TestClient) -> None:
    response = client.get("/users/me")

    assert response.json()["request_id"] == response.headers["X-Request-ID"]
