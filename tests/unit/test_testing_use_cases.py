from uuid import UUID, uuid4

import pytest

from app.application.ports.testing import ToolOutput
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.cve.lookup_cve import LookupCve
from app.application.use_cases.llm.plan_source import FixedPlanSource
from app.application.use_cases.testing.read_scans import GetScan, ListScanFindings, ListTestRuns
from app.application.use_cases.testing.run_scan_tests import RunScanTests
from app.application.use_cases.testing.start_tests import StartTests
from app.domain.entities.allowed_tool import AllowedTool
from app.domain.entities.cve import CveRecord
from app.domain.entities.domain import Domain
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.raw_finding import RawFinding
from app.domain.entities.user import User
from app.domain.errors import ConflictError, DomainNotVerifiedError, EntityNotFoundError
from app.domain.value_objects.domain_status import DomainStatus
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.role import Role
from app.domain.value_objects.severity import Severity
from app.domain.value_objects.verification_method import VerificationMethod
from app.infrastructure.security.aes_gcm_cipher import AesGcmCipher
from app.infrastructure.testing.fixed_planner import FixedProbePlanner
from tests.fakes import FakeClock, InMemoryAuditRepository, InMemoryDomainRepository
from tests.fakes_cve import FakeEpss, FakeKev, FakeNvd, InMemoryCveRepository
from tests.fakes_testing import (
    FakeRegistry,
    FakeRunner,
    ImmediateScheduler,
    InMemoryEndpointRepository,
    InMemoryFindingRepository,
    InMemoryScanRepository,
    InMemoryTestRunRepository,
    InMemoryToolRepository,
)
from tests.unit.test_secret_cipher import KEY

NUCLEI_POLICY = {
    "tags_allowlist": ["cve", "misconfig", "exposure", "tech"],
    "tags_denylist": ["dos", "intrusive", "fuzz", "bruteforce"],
    "rate_limit": 50,
    "timeout_s": 600,
}
LOG4J = "CVE-2021-44228"


def _user(role: Role = Role.ANALYST) -> User:
    return User(uuid4(), f"{uuid4()}@x.com", "h", role, None, False, FakeClock().now())


def _domain(owner: User, *, verified: bool = True) -> Domain:
    return Domain(
        uuid4(),
        owner.id,
        "example.com",
        VerificationMethod.DNS_TXT,
        "tok",
        DomainStatus.VERIFIED if verified else DomainStatus.PENDING,
        FakeClock().now() if verified else None,
    )


def _endpoint(
    domain: Domain, url: str, *, whitelisted: bool = True, in_scope: bool = True
) -> Endpoint:
    return Endpoint(uuid4(), uuid4(), domain.id, url, 200, (), whitelisted, in_scope)


class Env:
    def __init__(self) -> None:
        self.clock = FakeClock()
        self.owner = _user()
        self.domains = InMemoryDomainRepository()
        self.scans = InMemoryScanRepository()
        self.endpoints = InMemoryEndpointRepository()
        self.tools = InMemoryToolRepository(
            [
                AllowedTool(uuid4(), "headers", {"timeout_s": 30}, True),
                AllowedTool(uuid4(), "testssl", {"timeout_s": 300}, True),
                AllowedTool(uuid4(), "nuclei", NUCLEI_POLICY, True),
            ]
        )
        self.test_runs = InMemoryTestRunRepository()
        self.findings = InMemoryFindingRepository(self.test_runs)
        self.cves = InMemoryCveRepository()
        self.audit_repo = InMemoryAuditRepository()
        self.runners = {
            "headers": FakeRunner(),
            "testssl": FakeRunner(),
            "nuclei": FakeRunner(),
        }
        self.scheduler = ImmediateScheduler()
        self.cipher = AesGcmCipher(KEY)
        audit = RecordAction(self.audit_repo)
        lookup = LookupCve(self.cves, FakeNvd(), FakeEpss(), FakeKev(), self.clock)
        self.run = RunScanTests(
            domains=self.domains,
            scans=self.scans,
            endpoints=self.endpoints,
            tools=self.tools,
            test_runs=self.test_runs,
            findings=self.findings,
            cves=self.cves,
            lookup_cve=lookup,
            registry=FakeRegistry(self.runners),
            plan_source=FixedPlanSource(FixedProbePlanner()),
            cipher=self.cipher,
            audit=audit,
            clock=self.clock,
        )
        self.start = StartTests(
            self.domains, self.endpoints, self.scans, self.run, self.scheduler, audit, self.clock
        )
        self.get = GetScan(self.domains, self.scans)
        self.list_runs = ListTestRuns(self.domains, self.scans, self.test_runs)
        self.list_findings = ListScanFindings(self.domains, self.scans, self.findings)

    async def with_domain(self, *, verified: bool = True) -> Domain:
        domain = _domain(self.owner, verified=verified)
        await self.domains.save(domain)
        return domain


async def test_start_requires_a_verified_domain_and_testable_endpoints() -> None:
    env = Env()
    pending = await env.with_domain(verified=False)
    with pytest.raises(DomainNotVerifiedError):
        await env.start.execute(env.owner, pending.id)
    empty = _domain(env.owner)
    await env.domains.save(empty)
    env.endpoints.endpoints = [
        _endpoint(empty, "https://example.com", whitelisted=False),
        _endpoint(empty, "https://example.com/a", in_scope=False),
    ]
    with pytest.raises(ConflictError):
        await env.start.execute(env.owner, empty.id)
    assert env.scans.scans == {}


async def test_start_hides_other_users_domains() -> None:
    env = Env()
    domain = await env.with_domain()
    with pytest.raises(EntityNotFoundError):
        await env.start.execute(_user(), domain.id)
    admin_scan = await _started(env, domain, user=_user(Role.ADMIN))
    assert admin_scan.status is JobStatus.QUEUED


async def _started(env: Env, domain: Domain, user: User | None = None):  # type: ignore[no-untyped-def]
    if not env.endpoints.endpoints:
        env.endpoints.endpoints = [_endpoint(domain, "https://example.com/")]
    return await env.start.execute(user or env.owner, domain.id)


async def test_full_run_executes_the_plan_and_seals_results() -> None:
    env = Env()
    domain = await env.with_domain()
    env.endpoints.endpoints = [_endpoint(domain, "https://example.com/")]
    env.runners["headers"].output = ToolOutput(
        [RawFinding("Falta la cabecera CSP", Severity.MEDIUM, "sin CSP")], "HTTP 200"
    )
    env.runners["nuclei"].output = ToolOutput(
        [RawFinding("Log4j", Severity.CRITICAL, "evidencia", (LOG4J,))], "{}"
    )
    env.cves.records[LOG4J] = CveRecord(LOG4J, 10.0, None, 0.94, True, env.clock.now())

    scan = await env.start.execute(env.owner, domain.id)
    assert scan.status is JobStatus.QUEUED
    await env.scheduler.run_all()

    done = env.scans.scans[scan.id]
    assert done.status is JobStatus.DONE
    assert done.started_at is not None
    assert done.finished_at is not None
    runs = await env.list_runs.execute(env.owner, scan.id)
    assert sorted(r.tool_name for r in runs) == ["headers", "nuclei", "testssl"]
    assert all(r.status is JobStatus.DONE for r in runs)
    findings = {f.title: f for f in await env.list_findings.execute(env.owner, scan.id)}
    assert findings["Falta la cabecera CSP"].priority_score == 45.0
    assert findings["Log4j"].priority_score == 100.0
    assert findings["Log4j"].cve_ids == (LOG4J,)
    sealed = env.test_runs.results[runs[0].id]
    assert sealed is not None
    assert sealed.startswith(b"v1:")
    assert b"HTTP 200" not in sealed
    token = env.findings.evidence[findings["Log4j"].id]
    assert token is not None
    assert env.cipher.decrypt(token.decode(), f"scan-result:{findings['Log4j'].id}") == "evidencia"
    actions = env.audit_repo.actions()
    assert actions.count("scan.tests_started") == 1
    assert actions.count("scan.tests_finished") == 1


async def test_tool_failures_fail_the_run_but_not_the_scan() -> None:
    env = Env()
    domain = await env.with_domain()
    env.endpoints.endpoints = [_endpoint(domain, "https://example.com/")]
    env.runners["nuclei"].error = "nuclei no está instalada"
    scan = await _started(env, domain)
    await env.scheduler.run_all()
    assert env.scans.scans[scan.id].status is JobStatus.DONE
    runs = {r.tool_name: r for r in await env.list_runs.execute(env.owner, scan.id)}
    assert runs["nuclei"].status is JobStatus.FAILED
    assert runs["headers"].status is JobStatus.DONE
    assert b"v1:" in (env.test_runs.results[runs["nuclei"].id] or b"")


async def test_scan_fails_when_every_test_fails() -> None:
    env = Env()
    domain = await env.with_domain()
    env.endpoints.endpoints = [_endpoint(domain, "https://example.com/")]
    for runner in env.runners.values():
        runner.error = "caído"
    scan = await _started(env, domain)
    await env.scheduler.run_all()
    assert env.scans.scans[scan.id].status is JobStatus.FAILED


async def test_out_of_scope_endpoints_never_reach_a_tool() -> None:
    env = Env()
    domain = await env.with_domain()
    env.endpoints.endpoints = [
        _endpoint(domain, "https://example.com/"),
        _endpoint(domain, "https://evil.com/"),
    ]
    scan = await _started(env, domain)
    await env.scheduler.run_all()
    called = {url for runner in env.runners.values() for url, _ in runner.calls}
    assert called == {"https://example.com/"}
    assert len(await env.list_runs.execute(env.owner, scan.id)) == 3


async def test_inactive_or_missing_tools_are_skipped() -> None:
    env = Env()
    domain = await env.with_domain()
    env.endpoints.endpoints = [_endpoint(domain, "https://example.com/")]
    env.tools.tools["nuclei"] = AllowedTool(uuid4(), "nuclei", NUCLEI_POLICY, False)
    del env.tools.tools["testssl"]
    scan = await _started(env, domain)
    await env.scheduler.run_all()
    runs = await env.list_runs.execute(env.owner, scan.id)
    assert [r.tool_name for r in runs] == ["headers"]
    assert env.runners["nuclei"].calls == []


async def test_unverified_domain_at_run_time_fails_the_scan() -> None:
    env = Env()
    domain = await env.with_domain()
    scan = await _started(env, domain)
    env.domains.domains[domain.id] = _domain(env.owner, verified=False)
    env.domains.domains[domain.id] = Domain(**{**domain.__dict__, "status": DomainStatus.PENDING})
    await env.scheduler.run_all()
    assert env.scans.scans[scan.id].status is JobStatus.FAILED
    assert env.runners["headers"].calls == []


async def test_run_only_processes_queued_scans_once() -> None:
    env = Env()
    domain = await env.with_domain()
    scan = await _started(env, domain)
    await env.scheduler.run_all()
    before = len(env.runners["headers"].calls)
    assert await env.run.execute(scan.id) is None
    assert await env.run.execute(UUID(int=1)) is None
    assert len(env.runners["headers"].calls) == before


async def test_reading_a_scan_is_scoped_to_its_owner_or_admin() -> None:
    env = Env()
    domain = await env.with_domain()
    scan = await _started(env, domain)
    assert (await env.get.execute(env.owner, scan.id)).id == scan.id
    assert (await env.get.execute(_user(Role.ADMIN), scan.id)).id == scan.id
    for reader in (_user(), _user(Role.VIEWER)):
        with pytest.raises(EntityNotFoundError):
            await env.get.execute(reader, scan.id)
        with pytest.raises(EntityNotFoundError):
            await env.list_runs.execute(reader, scan.id)
        with pytest.raises(EntityNotFoundError):
            await env.list_findings.execute(reader, scan.id)
    with pytest.raises(EntityNotFoundError):
        await env.get.execute(env.owner, uuid4())
