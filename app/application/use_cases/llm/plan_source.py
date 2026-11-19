from collections.abc import Mapping, Sequence

import structlog

from app.application.llm_budget import TokenBudget
from app.application.ports.llm import (
    EndpointView,
    LlmGateway,
    PlanRequest,
    PlanResult,
    PlanSource,
    ToolView,
)
from app.application.ports.testing import ProbePlanner
from app.application.use_cases.llm.recorder import DecisionRecorder
from app.domain.entities.allowed_tool import AllowedTool
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.scan import Scan
from app.domain.errors import DomainError, LlmOutputRejectedError
from app.domain.errors_llm import LlmUnavailableError
from app.domain.services.plan_validation import validate_plan
from app.domain.value_objects.llm_kind import LlmKind

log = structlog.get_logger(__name__)


class FixedPlanSource:
    def __init__(self, planner: ProbePlanner) -> None:
        self._planner = planner

    async def plan(
        self,
        scan: Scan,
        domain_name: str,
        endpoints: Sequence[Endpoint],
        tools: Mapping[str, AllowedTool],
    ) -> PlanResult:
        return PlanResult(self._planner.plan(endpoints))


class LlmPlanSource:
    def __init__(
        self,
        gateway: LlmGateway,
        recorder: DecisionRecorder,
        budget: TokenBudget,
        fallback: PlanSource,
    ) -> None:
        self._gateway = gateway
        self._recorder = recorder
        self._budget = budget
        self._fallback = fallback

    async def plan(
        self,
        scan: Scan,
        domain_name: str,
        endpoints: Sequence[Endpoint],
        tools: Mapping[str, AllowedTool],
    ) -> PlanResult:
        result = await self._propose(scan, domain_name, endpoints, tools)
        if result is not None:
            return result
        return await self._fallback.plan(scan, domain_name, endpoints, tools)

    async def _propose(
        self,
        scan: Scan,
        domain_name: str,
        endpoints: Sequence[Endpoint],
        tools: Mapping[str, AllowedTool],
    ) -> PlanResult | None:
        if not endpoints or not self._budget.has_room(scan.id):
            return None
        request = PlanRequest(
            domain=domain_name,
            endpoints=tuple(
                EndpointView(e.id, e.url, e.http_status, e.technologies) for e in endpoints
            ),
            tools=tuple(ToolView(t.name, t.allowed_params) for t in tools.values() if t.active),
        )
        try:
            response = await self._gateway.plan(request)
        except LlmUnavailableError:
            log.warning("llm_plan_unavailable", scan_id=str(scan.id))
            return None
        except DomainError:
            return None
        if response.data is None:
            await self._recorder.record(
                scan.id,
                LlmKind.PLAN,
                request,
                response,
                validated=False,
                justification=response.error,
            )
            return None
        try:
            tests = validate_plan(
                response.data.tests, {e.id: e for e in endpoints}, tools, domain_name
            )
        except LlmOutputRejectedError as exc:
            await self._recorder.record(
                scan.id, LlmKind.PLAN, request, response, validated=False, justification=exc.message
            )
            log.warning("llm_plan_rejected", scan_id=str(scan.id), reason=exc.message)
            return None
        decision = await self._recorder.record(
            scan.id,
            LlmKind.PLAN,
            request,
            response,
            validated=True,
            justification=response.data.justification,
        )
        return PlanResult(tests, decision.id)
