from uuid import uuid4

from fastapi.testclient import TestClient

from app.domain.value_objects.role import Role
from tests.fakes import FakeDomainVerifier, InMemoryAuditRepository, InMemoryUserRepository
from tests.helpers import bearer, register_and_login


def _session(
    client: TestClient, users: InMemoryUserRepository, email: str, role: Role
) -> dict[str, str]:
    headers = bearer(register_and_login(client, email))
    users.set_role(email, role)
    return headers


def _create(
    client: TestClient, headers: dict[str, str], name: str = "example.com", method: str = "dns_txt"
) -> dict[str, object]:
    response = client.post(
        "/domains", json={"name": name, "verification_method": method}, headers=headers
    )
    assert response.status_code == 201, response.text
    body: dict[str, object] = response.json()
    return body


def test_create_domain_returns_dns_instructions(
    client: TestClient, users_repo: InMemoryUserRepository
) -> None:
    headers = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    body = _create(client, headers, "Example.COM")
    assert body["name"] == "example.com"
    assert body["status"] == "pending"
    assert body["verified_at"] is None
    verification = body["verification"]
    assert isinstance(verification, dict)
    assert verification["method"] == "dns_txt"
    assert verification["location"] == "_safeit-verify.example.com"
    assert str(verification["value"]).startswith("safeit-verification=")


def test_create_domain_returns_file_instructions(
    client: TestClient, users_repo: InMemoryUserRepository
) -> None:
    headers = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    verification = _create(client, headers, method="file")["verification"]
    assert isinstance(verification, dict)
    assert str(verification["location"]).startswith("/.well-known/safeit-")
    assert str(verification["location"]).endswith(".txt")


def test_create_domain_validation_and_conflicts(
    client: TestClient, users_repo: InMemoryUserRepository
) -> None:
    headers = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    bad_name = client.post(
        "/domains", json={"name": "localhost", "verification_method": "file"}, headers=headers
    )
    assert (bad_name.status_code, bad_name.json()["code"]) == (422, "invalid_domain_name")
    bad_method = client.post(
        "/domains", json={"name": "example.com", "verification_method": "ftp"}, headers=headers
    )
    assert bad_method.status_code == 422
    _create(client, headers)
    duplicate = client.post(
        "/domains", json={"name": "example.com", "verification_method": "file"}, headers=headers
    )
    assert (duplicate.status_code, duplicate.json()["code"]) == (409, "conflict")


def test_viewer_can_list_but_not_create(
    client: TestClient, users_repo: InMemoryUserRepository
) -> None:
    headers = _session(client, users_repo, "viewer@example.com", Role.VIEWER)
    denied = client.post(
        "/domains", json={"name": "example.com", "verification_method": "file"}, headers=headers
    )
    assert denied.status_code == 403
    listing = client.get("/domains", headers=headers)
    assert (listing.status_code, listing.json()) == (200, [])


def test_verify_flow(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
) -> None:
    headers = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    domain_id = _create(client, headers)["id"]
    failed = client.post(f"/domains/{domain_id}/verify", headers=headers)
    assert (failed.status_code, failed.json()["code"]) == (422, "domain_verification_failed")
    assert client.get(f"/domains/{domain_id}", headers=headers).json()["status"] == "pending"
    domain_verifier.verified_names.add("example.com")
    verified = client.post(f"/domains/{domain_id}/verify", headers=headers)
    assert verified.status_code == 200
    assert verified.json()["status"] == "verified"
    assert verified.json()["verified_at"] is not None
    assert client.get("/domains", headers=headers).json()[0]["status"] == "verified"


def test_domain_claimed_by_another_user(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
) -> None:
    first = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    second = _session(client, users_repo, "luis@example.com", Role.ANALYST)
    domain_id = _create(client, first)["id"]
    domain_verifier.verified_names.add("example.com")
    assert client.post(f"/domains/{domain_id}/verify", headers=first).status_code == 200
    response = client.post(
        "/domains", json={"name": "example.com", "verification_method": "file"}, headers=second
    )
    assert (response.status_code, response.json()["code"]) == (409, "domain_already_claimed")


def test_domains_are_private_to_their_owner(
    client: TestClient, users_repo: InMemoryUserRepository
) -> None:
    owner = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    stranger = _session(client, users_repo, "luis@example.com", Role.ANALYST)
    admin = _session(client, users_repo, "root@example.com", Role.ADMIN)
    domain_id = _create(client, owner)["id"]
    assert client.get("/domains", headers=stranger).json() == []
    assert client.get(f"/domains/{domain_id}", headers=stranger).status_code == 404
    assert client.post(f"/domains/{domain_id}/verify", headers=stranger).status_code == 404
    assert client.get(f"/domains/{domain_id}", headers=admin).status_code == 200
    assert client.post(f"/domains/{domain_id}/verify", headers=admin).status_code == 404
    assert client.get(f"/domains/{uuid4()}", headers=owner).status_code == 404
    assert client.get("/domains/not-a-uuid", headers=owner).status_code == 422


def test_domain_endpoints_require_authentication(client: TestClient) -> None:
    for method, path in (
        ("get", "/domains"),
        ("post", "/domains"),
        ("get", f"/domains/{uuid4()}"),
        ("post", f"/domains/{uuid4()}/verify"),
    ):
        assert getattr(client, method)(path).status_code == 401, (method, path)


def test_audit_is_admin_only_and_records_domain_events(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    audit_repo: InMemoryAuditRepository,
) -> None:
    analyst = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    admin = _session(client, users_repo, "root@example.com", Role.ADMIN)
    domain_id = _create(client, analyst)["id"]
    domain_verifier.verified_names.add("example.com")
    client.post(f"/domains/{domain_id}/verify", headers=analyst)

    assert client.get("/audit", headers=analyst).status_code == 403
    assert client.get("/audit/verify", headers=analyst).status_code == 403
    assert client.get("/audit").status_code == 401

    listing = client.get("/audit", headers=admin).json()
    entries = [e for e in listing if e["action"].startswith("domain.")]
    assert [e["action"] for e in entries] == ["domain.verified", "domain.created"]
    assert entries[0]["entity_id"] == domain_id
    assert entries[0]["detail"] == {"name": "example.com", "method": "dns_txt"}
    filtered = client.get("/audit", params={"action": "domain.created", "limit": 1}, headers=admin)
    assert [e["action"] for e in filtered.json()] == ["domain.created"]
    assert client.get("/audit", params={"limit": 500}, headers=admin).status_code == 422

    assert client.get("/audit/verify", headers=admin).json() == {
        "intact": True,
        "broken_at_id": None,
    }
    audit_repo.broken_at = 2
    assert client.get("/audit/verify", headers=admin).json() == {
        "intact": False,
        "broken_at_id": 2,
    }
