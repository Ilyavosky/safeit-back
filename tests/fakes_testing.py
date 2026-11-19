from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import replace
from typing import Any
from uuid import UUID

from app.application.ports.testing import ToolExecutionError, ToolOutput
from app.domain.entities.allowed_tool import AllowedTool
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.finding import Finding
from app.domain.entities.scan import Scan
from app.domain.entities.test_run import TestRun
from app.domain.errors import ToolNotAllowedError


class InMemoryScanRepository:
    def __init__(self) -> None:
        self.scans: dict[UUID, Scan] = {}

    async def add(self, scan: Scan) -> None:
        self.scans[scan.id] = scan

    async def get(self, scan_id: UUID) -> Scan | None:
        return self.scans.get(scan_id)

    async def save(self, scan: Scan) -> None:
        self.scans[scan.id] = scan


class InMemoryEndpointRepository:
    def __init__(self) -> None:
        self.endpoints: list[Endpoint] = []

    async def list_testable(self, domain_id: UUID) -> list[Endpoint]:
        return [
            e for e in self.endpoints if e.domain_id == domain_id and e.whitelisted and e.in_scope
        ]


class InMemoryToolRepository:
    def __init__(self, tools: Sequence[AllowedTool] = ()) -> None:
        self.tools = {t.name: t for t in tools}

    async def get_by_name(self, name: str) -> AllowedTool | None:
        return self.tools.get(name)

    async def list_active(self) -> list[AllowedTool]:
        return [t for t in self.tools.values() if t.active]


class InMemoryTestRunRepository:
    def __init__(self) -> None:
        self.runs: dict[UUID, TestRun] = {}
        self.results: dict[UUID, bytes | None] = {}

    async def add(self, run: TestRun) -> None:
        self.runs[run.id] = run

    async def save(self, run: TestRun, result_enc: bytes | None) -> None:
        self.runs[run.id] = run
        if result_enc is not None:
            self.results[run.id] = result_enc

    async def list_by_scan(self, scan_id: UUID) -> list[TestRun]:
        return [r for r in self.runs.values() if r.scan_id == scan_id]


class InMemoryFindingRepository:
    def __init__(self, test_runs: InMemoryTestRunRepository) -> None:
        self.findings: list[Finding] = []
        self.evidence: dict[UUID, bytes | None] = {}
        self._test_runs = test_runs

    async def add(self, finding: Finding, evidence_enc: bytes | None) -> None:
        self.findings.append(replace(finding))
        self.evidence[finding.id] = evidence_enc

    async def list_by_scan(self, scan_id: UUID) -> list[Finding]:
        run_ids = {r.id for r in await self._test_runs.list_by_scan(scan_id)}
        return [f for f in self.findings if f.test_run_id in run_ids]


class FakeRunner:
    def __init__(self, output: ToolOutput | None = None, error: str | None = None) -> None:
        self.output = output or ToolOutput(findings=[], raw="")
        self.error = error
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    async def run(self, url: str, params: Mapping[str, Any]) -> ToolOutput:
        self.calls.append((url, params))
        if self.error is not None:
            raise ToolExecutionError(self.error)
        return self.output


class FakeRegistry:
    def __init__(self, runners: Mapping[str, FakeRunner]) -> None:
        self.runners = dict(runners)

    def runner_for(self, tool: AllowedTool) -> FakeRunner:
        runner = self.runners.get(tool.name)
        if runner is None:
            raise ToolNotAllowedError(tool.name)
        return runner


class ImmediateScheduler:
    def __init__(self) -> None:
        self.jobs: list[Callable[[], Awaitable[None]]] = []

    def schedule(self, job: Callable[[], Awaitable[None]]) -> None:
        self.jobs.append(job)

    async def run_all(self) -> None:
        pending, self.jobs = self.jobs, []
        for job in pending:
            await job()

    async def aclose(self) -> None:
        return None
