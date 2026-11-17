import re

from fastapi.testclient import TestClient


def test_generates_request_id_when_missing(client: TestClient) -> None:
    response = client.get("/health")

    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["X-Request-ID"])


def test_keeps_valid_request_id_from_client(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "front-req-12345"})

    assert response.headers["X-Request-ID"] == "front-req-12345"


def test_replaces_invalid_request_id(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "bad id\twith spaces"})

    assert response.headers["X-Request-ID"] != "bad id\twith spaces"
    assert re.fullmatch(r"[0-9a-f]{32}", response.headers["X-Request-ID"])
