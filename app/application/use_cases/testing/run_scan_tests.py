import json
from uuid import UUID, uuid4

import structlog

from app.application.ports.clock import Clock
from app.application.ports.cve_catalog import CveRepository
from app.application.ports.repositories import DomainRepository
from app.application.ports.secret_cipher import SecretCipher
from app.application.ports.testing import (
    ProbePlanner,
    ToolExecutionError,
    ToolOutput,
    ToolRegistry,
)
from app.application.ports.testing_repositories import (
    EndpointRepository,
    FindingRepository,
    ScanRepository,
    TestRunRepository,
    ToolRepository,
)
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.cve.lookup_cve import LookupCve
from app.domain.entities.cve import CveRecord
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.finding import Finding
from app.domain.entities.planned_test import PlannedTest
from app.domain.entities.scan import Scan
from app.domain.entities.test_run import TestRun
from app.domain.errors import DomainError
from app.domain.services.finding_priority import finding_priority
from app.domain.services.risk_scoring import priority_score
from app.domain.services.scope_policy import ensure_url_in_scope
from app.domain.services.tool_policy import effective_params
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.remediation_status import RemediationStatus

log = structlog.get_logger(__name__)


class RunScanTests:
    def __init__(
        self,
        *,
        domains: DomainRepository,
        scans: ScanRepository,
        endpoints: EndpointRepository,
        tools: ToolRepository,
        test_runs: TestRunRepository,
        findings: FindingRepository,
        cves: CveRepository,
        lookup_cve: LookupCve,
        registry: ToolRegistry,
        planner: ProbePlanner,
        cipher: SecretCipher,
        audit: RecordAction,
        clock: Clock,
    ) -> None:
        self._domains = domains
        self._scans = scans
        self._endpoints = endpoints
        self._tools = tools
        self._test_runs = test_runs
        self._findings = findings
        self._cves = cves
        self._lookup_cve = lookup_cve
        self._registry = registry
        self._planner = planner
        self._cipher = cipher
        self._audit = audit
        self._clock = clock

    async def execute(self, scan_id: UUID) -> Scan | None:
        scan = await self._scans.get(scan_id)
        if scan is None or scan.status is not JobStatus.QUEUED:
            return None
        scan = scan.start(self._clock.now())
        await self._scans.save(scan)
        try:
            outcomes = await self._run_plan(scan)
        except Exception:
            log.exception("scan_tests_failed", scan_id=str(scan.id))
            outcomes = []
        planned = len(outcomes)
        succeeded = sum(1 for ok in outcomes if ok)
        status = JobStatus.DONE if planned and succeeded else JobStatus.FAILED
        finished = scan.finish(status, self._clock.now())
        await self._scans.save(finished)
        await self._audit.execute(
            "scan.tests_finished",
            user_id=scan.started_by,
            entity="scan",
            entity_id=scan.id,
            detail={"status": status.value, "tests": planned, "succeeded": succeeded},
        )
        return finished

    async def _run_plan(self, scan: Scan) -> list[bool]:
        domain = await self._domains.get_by_id(scan.domain_id)
        if domain is None or not domain.is_verified:
            return []
        endpoints = {e.id: e for e in await self._endpoints.list_testable(domain.id)}
        plan = self._planner.plan(list(endpoints.values()))
        outcomes: list[bool] = []
        for item in plan:
            endpoint = endpoints.get(item.endpoint_id)
            if endpoint is None:
                outcomes.append(False)
                continue
            outcomes.append(await self._run_one(scan, domain.name, endpoint, item))
        return outcomes

    async def _run_one(
        self, scan: Scan, domain_name: str, endpoint: Endpoint, item: PlannedTest
    ) -> bool:
        tool = await self._tools.get_by_name(item.tool_name)
        if tool is None or not tool.active:
            return False
        try:
            ensure_url_in_scope(endpoint.url, domain_name)
            params = effective_params(tool.name, item.params, tool.allowed_params)
            runner = self._registry.runner_for(tool)
        except DomainError as exc:
            log.warning("test_rejected", tool=item.tool_name, reason=exc.code)
            return False
        run = TestRun(
            id=uuid4(),
            scan_id=scan.id,
            endpoint_id=endpoint.id,
            tool_id=tool.id,
            tool_name=tool.name,
            params=params,
            status=JobStatus.QUEUED,
        )
        await self._test_runs.add(run)
        run = run.start(self._clock.now())
        await self._test_runs.save(run, None)
        try:
            output = await runner.run(endpoint.url, params)
        except ToolExecutionError as exc:
            failure = json.dumps({"error": str(exc)}, ensure_ascii=False)
            await self._test_runs.save(
                run.finish(JobStatus.FAILED, self._clock.now()), self._seal(failure, run.id)
            )
            return False
        await self._store_findings(run, endpoint, output)
        await self._test_runs.save(
            run.finish(JobStatus.DONE, self._clock.now()), self._seal(output.raw, run.id)
        )
        return True

    async def _store_findings(self, run: TestRun, endpoint: Endpoint, output: ToolOutput) -> None:
        for raw in output.findings:
            known = await self._known_cves(raw.cve_ids)
            priorities = [
                p
                for record in known
                if (p := priority_score(record.cvss_score, record.epss_score, record.in_cisa_kev))
                is not None
            ]
            finding_id = uuid4()
            finding = Finding(
                id=finding_id,
                test_run_id=run.id,
                endpoint_id=endpoint.id,
                title=raw.title,
                severity=raw.severity,
                priority_score=finding_priority(raw.severity, priorities),
                remediation_status=RemediationStatus.OPEN,
                detected_at=self._clock.now(),
                cve_ids=tuple(record.cve_id for record in known),
            )
            await self._findings.add(finding, self._seal(raw.evidence, finding_id))

    async def _known_cves(self, cve_ids: tuple[str, ...]) -> list[CveRecord]:
        records: list[CveRecord] = []
        for cve_id in cve_ids:
            record = await self._cves.get(cve_id)
            if record is None:
                try:
                    record = await self._lookup_cve.execute(cve_id)
                except DomainError:
                    continue
            records.append(record)
        return records

    def _seal(self, plaintext: str, entity_id: UUID) -> bytes:
        return self._cipher.encrypt(plaintext, f"scan-result:{entity_id}").encode("ascii")
