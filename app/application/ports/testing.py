from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from app.domain.entities.allowed_tool import AllowedTool
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.planned_test import PlannedTest
from app.domain.entities.raw_finding import RawFinding


class ToolExecutionError(Exception):
    pass


@dataclass(frozen=True)
class ToolOutput:
    findings: list[RawFinding]
    raw: str


class ToolRunner(Protocol):
    async def run(self, url: str, params: Mapping[str, Any]) -> ToolOutput: ...


class ToolRegistry(Protocol):
    def runner_for(self, tool: AllowedTool) -> ToolRunner: ...


class ProbePlanner(Protocol):
    def plan(self, endpoints: Sequence[Endpoint]) -> list[PlannedTest]: ...


class ScanScheduler(Protocol):
    def schedule(self, job: Callable[[], Awaitable[None]]) -> None: ...

    async def aclose(self) -> None: ...
