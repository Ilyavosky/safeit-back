from fastapi.testclient import TestClient
from httpx2 import Response

PASSWORD = "correct-horse-battery"
EMAIL = "ana@example.com"


def register(client: TestClient, email: str = EMAIL, password: str = PASSWORD) -> Response:
    return client.post("/auth/register", json={"email": email, "password": password})


def login(client: TestClient, email: str = EMAIL, password: str = PASSWORD) -> Response:
    return client.post("/auth/login", json={"email": email, "password": password})


def register_and_login(
    client: TestClient, email: str = EMAIL, password: str = PASSWORD
) -> Response:
    assert register(client, email, password).status_code == 201
    response = login(client, email, password)
    assert response.status_code == 200
    return response


def bearer(response: Response) -> dict[str, str]:
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def refresh_with(client: TestClient, raw_token: str | None) -> Response:
    headers = {"Cookie": f"safeit_refresh={raw_token}"} if raw_token else {}
    return client.post("/auth/refresh", headers=headers)
