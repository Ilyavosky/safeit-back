import asyncio
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from app.application.use_cases.recon.run_recon import RunReconScan
from app.domain.entities.discovered import DiscoveredService, HttpProbe
from app.domain.value_objects.role import Role
from tests.fakes import FakeDomainVerifier, InMemoryUserRepository
from tests.fakes_recon import (
    FakeEnumerator,
    FakeProber,
    FakeReconQueue,
    FakeResolver,
    FakeScanner,
)
from tests.fakes_testing import InMemoryScanRepository
from tests.helpers import bearer, register_and_login

PUBLIC = "93.184.216.34"


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


def _run(client: TestClient, scan_id: str, only_host: str | None = None) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    runner: RunReconScan = container.run_recon_scan
    asyncio.run(runner.execute(UUID(scan_id), only_host))


def test_recon_flow_from_start_to_whitelisted_endpoint(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    recon_queue: FakeReconQueue,
    enumerator: FakeEnumerator,
    resolver: FakeResolver,
    port_scanner: FakeScanner,
    prober: FakeProber,
) -> None:
    headers = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    domain_id = _verified_domain(client, headers, domain_verifier)
    enumerator.hosts = ["api.example.com"]
    resolver.table = {"example.com": [PUBLIC], "api.example.com": [PUBLIC]}
    port_scanner.result = {PUBLIC: [DiscoveredService(443, "tcp", "https", "nginx", None)]}
    prober.result = [HttpProbe("example.com", "https://example.com/", 200, ("Nginx",))]

    started = client.post(f"/domains/{domain_id}/scans", headers=headers)
    assert started.status_code == 202
    body = started.json()
    assert (body["type"], body["status"]) == ("recon", "queued")
    assert recon_queue.jobs[0][0] == UUID(body["id"])
    assert client.post(f"/domains/{domain_id}/scans", headers=headers).status_code == 409

    _run(client, body["id"])
    assert client.get(f"/scans/{body['id']}", headers=headers).json()["status"] == "done"

    assets = client.get("/assets", params={"domain": str(domain_id)}, headers=headers).json()
    assert [(a["kind"], a["value"]) for a in assets] == [
        ("ip", PUBLIC),
        ("subdomain", "api.example.com"),
        ("subdomain", "example.com"),
    ]
    host = next(a for a in assets if a["value"] == "example.com")
    detail = client.get(f"/assets/{host['id']}", headers=headers).json()
    endpoint = detail["endpoints"][0]
    assert endpoint["whitelisted"] is False
    ip = next(a for a in assets if a["kind"] == "ip")
    ip_detail = client.get(f"/assets/{ip['id']}", headers=headers).json()
    assert ip_detail["services"][0]["port"] == 443

    toggled = client.put(
        f"/endpoints/{endpoint['id']}/whitelist", json={"whitelisted": True}, headers=headers
    )
    assert toggled.status_code == 200
    assert toggled.json()["whitelisted"] is True

    rescan = client.post(f"/assets/{host['id']}/rescan", headers=headers)
    assert rescan.status_code == 202
    assert recon_queue.jobs[-1] == (UUID(rescan.json()["id"]), "example.com")
    assert client.post(f"/assets/{ip['id']}/rescan", headers=headers).status_code in {409}


def test_recon_validations_and_access_control(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    recon_queue: FakeReconQueue,
    scans_repo: InMemoryScanRepository,
) -> None:
    owner = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    pending = client.post(
        "/domains", json={"name": "pendiente.com", "verification_method": "file"}, headers=owner
    ).json()["id"]
    rejected = client.post(f"/domains/{pending}/scans", headers=owner)
    assert rejected.status_code == 422
    assert rejected.json()["code"] == "domain_not_verified"
    assert recon_queue.jobs == []

    domain_id = _verified_domain(client, owner, domain_verifier)
    viewer = _session(client, users_repo, "vi@example.com", Role.VIEWER)
    other = _session(client, users_repo, "bo@example.com", Role.ANALYST)
    assert client.post(f"/domains/{domain_id}/scans", headers=viewer).status_code == 403
    assert client.post(f"/domains/{domain_id}/scans", headers=other).status_code == 404
    assert client.post(f"/domains/{domain_id}/scans").status_code == 401
    assert client.get("/assets", params={"domain": str(domain_id)}).status_code == 401
    assert (
        client.get("/assets", params={"domain": str(domain_id)}, headers=other).status_code == 404
    )
    assert client.get("/assets").status_code in {401, 422}
    assert client.get(f"/assets/{uuid4()}", headers=owner).status_code == 404
    assert client.post(f"/assets/{uuid4()}/rescan", headers=owner).status_code == 404
    assert (
        client.put(
            f"/endpoints/{uuid4()}/whitelist", json={"whitelisted": True}, headers=owner
        ).status_code
        == 404
    )


def test_queue_outage_returns_503_and_frees_the_domain(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    recon_queue: FakeReconQueue,
) -> None:
    headers = _session(client, users_repo, "ana@example.com", Role.ANALYST)
    domain_id = _verified_domain(client, headers, domain_verifier)
    recon_queue.down = True
    down = client.post(f"/domains/{domain_id}/scans", headers=headers)
    assert down.status_code == 503
    assert down.json()["code"] == "queue_unavailable"
    recon_queue.down = False
    assert client.post(f"/domains/{domain_id}/scans", headers=headers).status_code == 202
