from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from app.application.ports.testing import ToolOutput
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.raw_finding import RawFinding
from app.domain.value_objects.role import Role
from app.domain.value_objects.severity import Severity
from tests.fakes import FakeDomainVerifier, InMemoryUserRepository
from tests.fakes_testing import FakeRunner, ImmediateScheduler, InMemoryEndpointRepository
from tests.helpers import bearer, register_and_login


def _session(
    client: TestClient, users: InMemoryUserRepository, email: str, role: Role
) -> dict[str, str]:
    headers = bearer(register_and_login(client, email))
    users.set_role(email, role)
    return headers


def _verified_domain(
    client: TestClient, headers: dict[str, str], verifier: FakeDomainVerifier
) -> UUID:
    created = client.post(
        "/domains", json={"name": "example.com", "verification_method": "dns_txt"}, headers=headers
    )
    domain_id = UUID(created.json()["id"])
    verifier.verified_names.add("example.com")
    assert client.post(f"/domains/{domain_id}/verify", headers=headers).status_code == 200
    return domain_id


def _endpoint(domain_id: UUID, url: str = "https://example.com/") -> Endpoint:
    return Endpoint(uuid4(), uuid4(), domain_id, url, 200, (), True, True)


def test_start_tests_runs_the_plan_and_exposes_results(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    endpoints_repo: InMemoryEndpointRepository,
    scheduler: ImmediateScheduler,
    runners: dict[str, FakeRunner],
) -> None:
    headers = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    domain_id = _verified_domain(client, headers, domain_verifier)
    endpoints_repo.endpoints = [_endpoint(domain_id)]
    runners["headers"].output = ToolOutput(
        [RawFinding("Falta la cabecera CSP", Severity.MEDIUM, "sin CSP")], "HTTP 200"
    )

    started = client.post(f"/domains/{domain_id}/tests", headers=headers)
    assert started.status_code == 202
    scan_id = started.json()["id"]
    assert started.json()["status"] == "queued"
    assert started.json()["type"] == "tests"

    import asyncio

    asyncio.run(scheduler.run_all())

    scan = client.get(f"/scans/{scan_id}", headers=headers).json()
    assert scan["status"] == "done"
    runs = client.get(f"/scans/{scan_id}/test-runs", headers=headers).json()
    assert sorted(r["tool"] for r in runs) == ["headers", "nuclei", "testssl"]
    assert all(
        set(r) == {"id", "endpoint_id", "tool", "params", "status", "started_at", "finished_at"}
        for r in runs
    )
    findings = client.get(f"/scans/{scan_id}/findings", headers=headers).json()
    assert [(f["title"], f["severity"], f["priority_score"]) for f in findings] == [
        ("Falta la cabecera CSP", "medium", 45.0)
    ]
    assert "evidence" not in findings[0]


def test_start_tests_validates_domain_state_and_role(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    endpoints_repo: InMemoryEndpointRepository,
) -> None:
    owner = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    pending = client.post(
        "/domains", json={"name": "pendiente.com", "verification_method": "file"}, headers=owner
    ).json()["id"]
    unverified = client.post(f"/domains/{pending}/tests", headers=owner)
    assert unverified.status_code == 422
    assert unverified.json()["code"] == "domain_not_verified"

    domain_id = _verified_domain(client, owner, domain_verifier)
    empty = client.post(f"/domains/{domain_id}/tests", headers=owner)
    assert empty.status_code == 409

    endpoints_repo.endpoints = [_endpoint(domain_id)]
    viewer = _session(client, users_repo, "vi@example.com", Role.VIEWER)
    assert client.post(f"/domains/{domain_id}/tests", headers=viewer).status_code == 403
    other = _session(client, users_repo, "bo@example.com", Role.ANALYST)
    assert client.post(f"/domains/{domain_id}/tests", headers=other).status_code == 404
    assert client.post(f"/domains/{domain_id}/tests").status_code == 401
    assert client.post(f"/domains/{uuid4()}/tests", headers=owner).status_code == 404


def test_scan_reads_are_private_to_owner_and_admin(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    endpoints_repo: InMemoryEndpointRepository,
) -> None:
    owner = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    domain_id = _verified_domain(client, owner, domain_verifier)
    endpoints_repo.endpoints = [_endpoint(domain_id)]
    scan_id = client.post(f"/domains/{domain_id}/tests", headers=owner).json()["id"]
    paths = [f"/scans/{scan_id}", f"/scans/{scan_id}/test-runs", f"/scans/{scan_id}/findings"]

    other = _session(client, users_repo, "bo@example.com", Role.ANALYST)
    admin = _session(client, users_repo, "ad@example.com", Role.ADMIN)
    for path in paths:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=other).status_code == 404
        assert client.get(path, headers=admin).status_code == 200
    assert client.get(f"/scans/{uuid4()}", headers=owner).status_code == 404
    assert client.get("/scans/not-a-uuid", headers=owner).status_code == 422
