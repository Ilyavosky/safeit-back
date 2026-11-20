from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from uuid import UUID

from fastapi.testclient import TestClient

from app.application.ports.public_analysis import TlsObservation, WebObservation
from app.application.use_cases.public.run_analysis import RunPublicAnalysis
from app.config import Settings
from app.container import Container
from app.domain.entities.llm_proposals import PublicSummaryDraft
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.role import Role
from tests.fakes import FakeClock, InMemoryAuditRepository, InMemoryUserRepository
from tests.fakes_llm import FakeLlmGateway
from tests.fakes_public import (
    FakeCtSource,
    FakePublicDns,
    FakePublicQueue,
    FakeWebFetcher,
    InMemoryPublicAnalysisRepository,
)
from tests.fakes_recon import FakeEnumerator
from tests.helpers import bearer, register_and_login

BODY = {"domain": "ejemplo.com", "accept_notice": True}


def _headers(client: TestClient, email: str = "ana@example.com") -> dict[str, str]:
    return bearer(register_and_login(client, email))


def test_start_requires_authentication(client: TestClient) -> None:
    assert client.post("/public-analyses", json=BODY).status_code == 401


def test_any_authenticated_user_can_start_and_the_job_is_queued(
    client: TestClient, public_queue: FakePublicQueue, audit_repo: InMemoryAuditRepository
) -> None:
    response = client.post("/public-analyses", json=BODY, headers=_headers(client))

    assert response.status_code == 202
    body = response.json()
    assert body["domain"] == "ejemplo.com"
    assert body["status"] == "queued"
    assert public_queue.enqueued == [UUID(body["id"])]
    actions = [entry.action for entry in audit_repo.entries]
    assert "public_analysis.started" in actions


def test_notice_must_be_accepted(client: TestClient, public_queue: FakePublicQueue) -> None:
    response = client.post(
        "/public-analyses",
        json={"domain": "ejemplo.com", "accept_notice": False},
        headers=_headers(client),
    )

    assert response.status_code == 422
    assert response.json()["code"] == "notice_not_accepted"
    assert public_queue.enqueued == []


def test_blocked_and_protected_targets_are_refused(
    make_client: Callable[..., TestClient],
) -> None:
    client = make_client(custom_settings=Settings(cors_origins=["https://safeit.app"]))
    headers = _headers(client)

    for domain in ("agencia.gov", "safeit.app", "api.safeit.app", "algo.internal"):
        response = client.post(
            "/public-analyses", json={"domain": domain, "accept_notice": True}, headers=headers
        )
        assert response.status_code == 422, domain
        assert response.json()["code"] == "public_target_not_allowed"


def test_only_one_active_analysis_per_user(client: TestClient) -> None:
    headers = _headers(client)
    assert client.post("/public-analyses", json=BODY, headers=headers).status_code == 202

    second = client.post("/public-analyses", json=BODY, headers=headers)

    assert second.status_code == 409


def test_daily_limit_is_enforced(
    client: TestClient, public_repo: InMemoryPublicAnalysisRepository, clock: FakeClock
) -> None:
    headers = _headers(client)
    for _ in range(5):
        created = client.post("/public-analyses", json=BODY, headers=headers).json()
        stored = public_repo.analyses[UUID(created["id"])]
        public_repo.analyses[stored.id] = stored.finish(JobStatus.DONE, clock.now())
        clock.advance(minutes=2)

    response = client.post("/public-analyses", json=BODY, headers=headers)

    assert response.status_code == 429


def test_queue_failure_marks_the_analysis_failed(
    client: TestClient,
    public_queue: FakePublicQueue,
    public_repo: InMemoryPublicAnalysisRepository,
) -> None:
    public_queue.unavailable = True

    response = client.post("/public-analyses", json=BODY, headers=_headers(client))

    assert response.status_code == 503
    assert [a.status for a in public_repo.analyses.values()] == [JobStatus.FAILED]


def test_other_users_cannot_read_an_analysis_but_admins_can(
    client: TestClient, users_repo: InMemoryUserRepository
) -> None:
    owner = _headers(client, "dueno@example.com")
    stranger = _headers(client, "intruso@example.com")
    admin = _headers(client, "admin@example.com")
    users_repo.set_role("admin@example.com", Role.ADMIN)
    created = client.post("/public-analyses", json=BODY, headers=owner).json()

    assert client.get(f"/public-analyses/{created['id']}", headers=stranger).status_code == 404
    assert client.get(f"/public-analyses/{created['id']}", headers=admin).status_code == 200
    assert client.get(f"/public-analyses/{created['id']}", headers=owner).status_code == 200


def test_list_only_returns_own_analyses(client: TestClient) -> None:
    mine = _headers(client, "mia@example.com")
    other = _headers(client, "otra@example.com")
    client.post("/public-analyses", json=BODY, headers=mine)

    assert len(client.get("/public-analyses", headers=mine).json()) == 1
    assert client.get("/public-analyses", headers=other).json() == []


async def test_run_builds_hosts_stats_and_llm_summary(
    client: TestClient,
    public_repo: InMemoryPublicAnalysisRepository,
    public_dns: FakePublicDns,
    ct_source: FakeCtSource,
    web_fetcher: FakeWebFetcher,
    enumerator: FakeEnumerator,
    llm: FakeLlmGateway,
    clock: FakeClock,
) -> None:
    created = client.post("/public-analyses", json=BODY, headers=_headers(client)).json()
    enumerator.hosts = ["api.ejemplo.com", "www.ejemplo.com", "ajeno.otro.com"]
    ct_source.names = ["blog.ejemplo.com", "viejo.ejemplo.com"]
    public_dns.cname_data["blog.ejemplo.com"] = ["d1.cloudfront.net"]
    web_fetcher.observations = {
        "ejemplo.com": WebObservation(
            200,
            "text/html",
            "Inicio",
            None,
            {"Server": "nginx/1.18.0", "Strict-Transport-Security": "x"},
            "",
            TlsObservation("Let's Encrypt", True, clock.now().replace(year=clock.now().year + 1)),
        ),
        "api.ejemplo.com": WebObservation(200, "application/json", None, None, {}, ""),
        "blog.ejemplo.com": WebObservation(200, "text/html", "Mi blog", None, {}, ""),
    }
    llm.public_data = PublicSummaryDraft("El dominio tiene un sitio y una API.", ("Hay un blog.",))
    use_case = RunPublicAnalysis(
        public_repo,
        public_dns,
        enumerator,
        ct_source,
        web_fetcher,
        llm,
        clock,
    )

    await use_case.execute(UUID(created["id"]))

    stored = public_repo.analyses[UUID(created["id"])]
    assert stored.status is JobStatus.DONE
    hosts = {h.host: h for h in public_repo.hosts[stored.id]}
    assert set(hosts) == {
        "ejemplo.com",
        "www.ejemplo.com",
        "api.ejemplo.com",
        "blog.ejemplo.com",
        "viejo.ejemplo.com",
    }
    assert hosts["api.ejemplo.com"].kind.value == "api"
    assert hosts["blog.ejemplo.com"].kind.value == "blog"
    assert hosts["blog.ejemplo.com"].provider == "Amazon CloudFront"
    assert hosts["viejo.ejemplo.com"].kind.value == "no_service"
    assert hosts["ejemplo.com"].technologies == ("nginx",)
    assert stored.stats["total_hosts"] == 5
    assert stored.stats["dns"]["spf"] is True
    assert stored.stats["without_hsts"] == 2
    assert stored.summary is not None
    assert "Hay un blog." in stored.summary
    assert stored.summary_model == "fake-model"
    assert llm.calls[0][0] == "public"


async def test_run_without_llm_still_completes_without_summary(
    client: TestClient,
    public_repo: InMemoryPublicAnalysisRepository,
    public_dns: FakePublicDns,
    ct_source: FakeCtSource,
    web_fetcher: FakeWebFetcher,
    enumerator: FakeEnumerator,
    clock: FakeClock,
) -> None:
    created = client.post("/public-analyses", json=BODY, headers=_headers(client)).json()
    use_case = RunPublicAnalysis(
        public_repo, public_dns, enumerator, ct_source, web_fetcher, None, clock
    )

    await use_case.execute(UUID(created["id"]))

    stored = public_repo.analyses[UUID(created["id"])]
    assert stored.status is JobStatus.DONE
    assert stored.summary is None


async def test_run_failure_is_recorded_without_leaking_details(
    client: TestClient,
    public_repo: InMemoryPublicAnalysisRepository,
    ct_source: FakeCtSource,
    web_fetcher: FakeWebFetcher,
    enumerator: FakeEnumerator,
    clock: FakeClock,
) -> None:
    class BrokenDns(FakePublicDns):
        async def apex(self, domain: str):  # type: ignore[no-untyped-def]
            raise RuntimeError("secreto interno")

    created = client.post("/public-analyses", json=BODY, headers=_headers(client)).json()
    use_case = RunPublicAnalysis(
        public_repo, BrokenDns(), enumerator, ct_source, web_fetcher, None, clock
    )

    await use_case.execute(UUID(created["id"]))

    stored = public_repo.analyses[UUID(created["id"])]
    assert stored.status is JobStatus.FAILED
    assert stored.error == "El análisis no pudo completarse."


async def test_run_caps_the_number_of_hosts(
    client: TestClient,
    public_repo: InMemoryPublicAnalysisRepository,
    public_dns: FakePublicDns,
    ct_source: FakeCtSource,
    web_fetcher: FakeWebFetcher,
    enumerator: FakeEnumerator,
    clock: FakeClock,
) -> None:
    created = client.post("/public-analyses", json=BODY, headers=_headers(client)).json()
    ct_source.names = [f"h{i}.ejemplo.com" for i in range(120)]
    use_case = RunPublicAnalysis(
        public_repo, public_dns, enumerator, ct_source, web_fetcher, None, clock
    )

    await use_case.execute(UUID(created["id"]))

    stored = public_repo.analyses[UUID(created["id"])]
    assert stored.stats["total_hosts"] == 50
    assert stored.stats["truncated"] is True
    assert len(web_fetcher.fetched) == 50


async def test_expired_analyses_are_purged_and_hidden(
    client: TestClient,
    public_repo: InMemoryPublicAnalysisRepository,
    clock: FakeClock,
) -> None:
    headers = _headers(client)
    created = client.post("/public-analyses", json=BODY, headers=headers).json()
    stored = public_repo.analyses[UUID(created["id"])]
    public_repo.analyses[stored.id] = replace(stored, expires_at=clock.now() - timedelta(seconds=1))

    assert client.get(f"/public-analyses/{created['id']}", headers=headers).status_code == 404
    container: Container = client.app.state.container  # type: ignore[attr-defined]
    assert await container.purge_public_analyses.execute() == 1
    assert public_repo.analyses == {}
