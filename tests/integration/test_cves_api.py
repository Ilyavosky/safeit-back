from fastapi.testclient import TestClient

from app.application.ports.cve_catalog import NvdCve
from tests.fakes_cve import FakeNvd, InMemoryCveRepository
from tests.helpers import bearer, register_and_login

LOG4J = "CVE-2021-44228"


def test_cve_endpoint_requires_authentication(client: TestClient) -> None:
    assert client.get(f"/cves/{LOG4J}").status_code == 401


def test_cve_lookup_returns_scores_and_priority(
    client: TestClient, nvd: FakeNvd, cve_repo: InMemoryCveRepository
) -> None:
    headers = bearer(register_and_login(client))
    nvd.by_id[LOG4J] = NvdCve(LOG4J, 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    response = client.get(f"/cves/{LOG4J.lower()}", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["cve_id"] == LOG4J
    assert body["cvss_score"] == 10.0
    assert body["priority_score"] == 100.0
    assert LOG4J in cve_repo.records
    assert client.get(f"/cves/{LOG4J}", headers=headers).status_code == 200
    assert nvd.lookups == [LOG4J]


def test_cve_errors_use_the_uniform_body(client: TestClient, nvd: FakeNvd) -> None:
    headers = bearer(register_and_login(client))
    invalid = client.get("/cves/not-a-cve", headers=headers)
    assert invalid.status_code == 422
    assert invalid.json()["code"] == "invalid_cve_id"
    missing = client.get("/cves/CVE-2000-0001", headers=headers)
    assert missing.status_code == 404
    nvd.fail_lookup = True
    down = client.get("/cves/CVE-2000-0002", headers=headers)
    assert down.status_code == 503
    assert down.json()["code"] == "feed_unavailable"
    assert set(down.json()) == {"code", "message", "request_id"}
