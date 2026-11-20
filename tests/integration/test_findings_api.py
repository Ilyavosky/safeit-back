import asyncio
import io
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from pypdf import PdfReader

from app.application.ports.testing import ToolOutput
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.raw_finding import RawFinding
from app.domain.value_objects.role import Role
from app.domain.value_objects.severity import Severity
from tests.fakes import FakeDomainVerifier, InMemoryUserRepository
from tests.fakes_testing import FakeRunner, ImmediateScheduler, InMemoryEndpointRepository
from tests.helpers import bearer, register_and_login

OWNER = "ana@example.com"


def _session(
    client: TestClient, users: InMemoryUserRepository, email: str, role: Role
) -> dict[str, str]:
    headers = bearer(register_and_login(client, email))
    users.set_role(email, role)
    return headers


def _scan_with_findings(
    client: TestClient,
    users: InMemoryUserRepository,
    verifier: FakeDomainVerifier,
    endpoints: InMemoryEndpointRepository,
    scheduler: ImmediateScheduler,
    runners: dict[str, FakeRunner],
) -> tuple[dict[str, str], UUID, UUID]:
    headers = _session(client, users, OWNER, Role.ANALYST)
    created = client.post(
        "/domains", json={"name": "example.com", "verification_method": "dns_txt"}, headers=headers
    )
    domain_id = UUID(created.json()["id"])
    verifier.verified_names.add("example.com")
    client.post(f"/domains/{domain_id}/verify", headers=headers)
    endpoints.endpoints = [
        Endpoint(uuid4(), uuid4(), domain_id, "https://example.com/", 200, (), True, True)
    ]
    runners["headers"].output = ToolOutput(
        [RawFinding("Falta CSP", Severity.MEDIUM, "x"), RawFinding("Sin HSTS", Severity.LOW, "x")],
        "ok",
    )
    runners["nuclei"].output = ToolOutput([RawFinding("Panel expuesto", Severity.HIGH, "x")], "{}")
    scan_id = UUID(client.post(f"/domains/{domain_id}/tests", headers=headers).json()["id"])
    asyncio.run(scheduler.run_all())
    return headers, domain_id, scan_id


def test_listing_filters_sorting_and_cursor_pagination(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    endpoints_repo: InMemoryEndpointRepository,
    scheduler: ImmediateScheduler,
    runners: dict[str, FakeRunner],
) -> None:
    headers, domain_id, scan_id = _scan_with_findings(
        client, users_repo, domain_verifier, endpoints_repo, scheduler, runners
    )
    page = client.get("/findings", headers=headers).json()
    assert [f["title"] for f in page["items"]] == ["Panel expuesto", "Falta CSP", "Sin HSTS"]
    assert {f["status"] for f in page["items"]} == {"confirmed"}
    assert page["next_cursor"] is None

    first = client.get("/findings?limit=2", headers=headers).json()
    assert len(first["items"]) == 2
    assert first["next_cursor"]
    second = client.get(f"/findings?limit=2&cursor={first['next_cursor']}", headers=headers).json()
    assert [f["title"] for f in second["items"]] == ["Sin HSTS"]
    assert second["next_cursor"] is None
    seen = [f["id"] for f in first["items"] + second["items"]]
    assert len(set(seen)) == 3

    high = client.get("/findings?severity=high", headers=headers).json()["items"]
    assert [f["title"] for f in high] == ["Panel expuesto"]
    by_domain = client.get(f"/findings?domain_id={domain_id}&scan_id={scan_id}", headers=headers)
    assert len(by_domain.json()["items"]) == 3
    assert client.get(f"/findings?domain_id={uuid4()}", headers=headers).status_code == 404
    asset = page["items"][0]["asset_id"]
    assert len(client.get(f"/findings?asset_id={asset}", headers=headers).json()["items"]) == 3
    assert client.get(f"/findings?asset_id={uuid4()}", headers=headers).json()["items"] == []
    by_detected = client.get("/findings?sort=detected&limit=100", headers=headers)
    assert len(by_detected.json()["items"]) == 3
    assert client.get("/findings?cursor=basura", headers=headers).status_code == 422
    assert client.get("/findings?limit=0", headers=headers).status_code == 422
    assert client.get("/findings?status=nope", headers=headers).status_code == 422


def test_status_transitions_roles_and_audit(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    endpoints_repo: InMemoryEndpointRepository,
    scheduler: ImmediateScheduler,
    runners: dict[str, FakeRunner],
) -> None:
    headers, _, _ = _scan_with_findings(
        client, users_repo, domain_verifier, endpoints_repo, scheduler, runners
    )
    finding = client.get("/findings", headers=headers).json()["items"][0]
    url = f"/findings/{finding['id']}/status"

    moved = client.patch(url, json={"status": "in_progress"}, headers=headers)
    assert moved.status_code == 200
    assert moved.json()["remediation_status"] == "in_progress"
    assert moved.json()["status"] == "in_remediation"
    done = client.patch(url, json={"status": "fixed"}, headers=headers)
    assert done.json()["status"] == "resolved"

    refused = client.patch(url, json={"status": "open"}, headers=headers)
    assert refused.status_code == 409
    assert refused.json()["code"] == "invalid_status_transition"
    reopened = client.patch(
        url, json={"status": "open", "reason": "Volvió a aparecer en producción"}, headers=headers
    )
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "confirmed"
    assert client.patch(url, json={"status": "bogus"}, headers=headers).status_code == 422

    users_repo.set_role(OWNER, Role.VIEWER)
    assert client.get(f"/findings/{finding['id']}", headers=headers).status_code == 200
    forbidden = client.patch(url, json={"status": "fixed"}, headers=headers)
    assert forbidden.status_code == 403
    assert client.get("/findings", headers=headers).status_code == 200


def test_other_users_cannot_see_or_change_findings(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    endpoints_repo: InMemoryEndpointRepository,
    scheduler: ImmediateScheduler,
    runners: dict[str, FakeRunner],
) -> None:
    headers, _, scan_id = _scan_with_findings(
        client, users_repo, domain_verifier, endpoints_repo, scheduler, runners
    )
    finding = client.get("/findings", headers=headers).json()["items"][0]
    stranger = _session(client, users_repo, "eve@example.com", Role.ANALYST)
    assert client.get(f"/findings/{finding['id']}", headers=stranger).status_code == 404
    assert (
        client.patch(
            f"/findings/{finding['id']}/status", json={"status": "fixed"}, headers=stranger
        ).status_code
        == 404
    )
    assert client.get("/findings", headers=stranger).json()["items"] == []
    assert client.get(f"/reports/{scan_id}", headers=stranger).status_code == 404
    assert client.get(f"/reports/{scan_id}/pdf", headers=stranger).status_code == 404
    assert client.get(f"/dashboard/summary?scan_id={scan_id}", headers=stranger).status_code == 404
    admin = _session(client, users_repo, "root@example.com", Role.ADMIN)
    assert client.get(f"/findings/{finding['id']}", headers=admin).status_code == 200
    assert len(client.get("/findings", headers=admin).json()["items"]) == 3
    assert client.get("/findings", headers={}).status_code == 401


def test_dashboard_and_report_show_the_same_numbers(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    endpoints_repo: InMemoryEndpointRepository,
    scheduler: ImmediateScheduler,
    runners: dict[str, FakeRunner],
    finding_query: object,
) -> None:
    headers, domain_id, scan_id = _scan_with_findings(
        client, users_repo, domain_verifier, endpoints_repo, scheduler, runners
    )
    report = client.get(f"/reports/{scan_id}", headers=headers)
    assert report.status_code == 200
    body = report.json()
    by_scan = client.get(f"/dashboard/summary?scan_id={scan_id}", headers=headers).json()
    latest = client.get("/dashboard/summary", headers=headers).json()
    by_domain = client.get(f"/dashboard/summary?domain_id={domain_id}", headers=headers).json()
    expected = {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0}
    assert body["severity_counts"] == expected
    for dashboard in (by_scan, latest, by_domain):
        assert dashboard["severity_counts"] == body["severity_counts"]
        assert dashboard["total_findings"] == body["total_findings"] == 3
    assert by_scan["scans"]["done"] == 1
    assert by_scan["remediation_counts"] == {"open": 3, "in_progress": 0, "fixed": 0}
    assert len(by_scan["latest_findings"]) == 3

    finding = by_scan["latest_findings"][0]
    client.patch(
        f"/findings/{finding['id']}/status", json={"status": "in_progress"}, headers=headers
    )
    after = client.get(f"/dashboard/summary?scan_id={scan_id}", headers=headers).json()
    again = client.get(f"/reports/{scan_id}", headers=headers).json()
    assert after["severity_counts"] == again["severity_counts"]
    assert after["remediation_counts"]["in_progress"] == 1


def test_report_content_recommendations_and_pdf(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    endpoints_repo: InMemoryEndpointRepository,
    scheduler: ImmediateScheduler,
    runners: dict[str, FakeRunner],
) -> None:
    headers, _, scan_id = _scan_with_findings(
        client, users_repo, domain_verifier, endpoints_repo, scheduler, runners
    )
    body = client.get(f"/reports/{scan_id}", headers=headers).json()
    assert body["domain"] == "example.com"
    assert body["generated_with_llm"] is False
    assert "3 hallazgos activos" in body["summary"]
    recs = body["recommendations"]
    assert [r["priority"] for r in recs] == [1, 2, 3]
    assert [r["finding_title"] for r in recs] == ["Panel expuesto", "Falta CSP", "Sin HSTS"]
    assert {r["status"] for r in recs} == {"pending"}

    pdf = client.get(f"/reports/{scan_id}/pdf", headers=headers)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF")
    text = "".join(page.extract_text() for page in PdfReader(io.BytesIO(pdf.content)).pages)
    assert "Resumen ejecutivo" in text
    assert "example.com" in text
    assert "Total de hallazgos activos: 3" in text
    assert text.index("Panel expuesto") < text.index("Falta CSP") < text.index("Sin HSTS")
    assert "Hallazgos por severidad" in text

    first = recs[0]["id"]
    updated = client.patch(
        f"/recommendations/{first}", json={"status": "in_progress"}, headers=headers
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "in_progress"
    refreshed = client.get(f"/reports/{scan_id}", headers=headers).json()["recommendations"]
    assert refreshed[0]["status"] == "in_progress"
    assert (
        client.patch(f"/recommendations/{first}", json={"status": "x"}, headers=headers).status_code
        == 422
    )
    assert (
        client.patch(
            f"/recommendations/{uuid4()}", json={"status": "done"}, headers=headers
        ).status_code
        == 404
    )
    users_repo.set_role(OWNER, Role.VIEWER)
    assert (
        client.patch(
            f"/recommendations/{first}", json={"status": "done"}, headers=headers
        ).status_code
        == 403
    )
    assert client.get(f"/reports/{scan_id}/pdf", headers=headers).status_code == 200


def test_report_is_not_found_before_it_exists(
    client: TestClient,
    users_repo: InMemoryUserRepository,
    domain_verifier: FakeDomainVerifier,
    endpoints_repo: InMemoryEndpointRepository,
    scheduler: ImmediateScheduler,
) -> None:
    headers = _session(client, users_repo, OWNER, Role.ANALYST)
    domain_id = UUID(
        client.post(
            "/domains",
            json={"name": "example.com", "verification_method": "dns_txt"},
            headers=headers,
        ).json()["id"]
    )
    domain_verifier.verified_names.add("example.com")
    client.post(f"/domains/{domain_id}/verify", headers=headers)
    endpoints_repo.endpoints = [
        Endpoint(uuid4(), uuid4(), domain_id, "https://example.com/", 200, (), True, True)
    ]
    scan_id = client.post(f"/domains/{domain_id}/tests", headers=headers).json()["id"]
    assert client.get(f"/reports/{scan_id}", headers=headers).status_code == 404
    assert client.get(f"/reports/{uuid4()}", headers=headers).status_code == 404
