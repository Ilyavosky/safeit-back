import json
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit
from uuid import UUID

from app.domain.entities.allowed_tool import AllowedTool
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.llm_proposals import ProposedTest
from app.domain.entities.planned_test import PlannedTest
from app.domain.errors import LlmOutputRejectedError, OutOfScopeError, ToolNotAllowedError
from app.domain.services.scope_policy import ensure_url_in_scope
from app.domain.services.tool_policy import effective_params

MAX_PLANNED_TESTS = 200


def validate_plan(
    proposed: Sequence[ProposedTest],
    endpoints: Mapping[UUID, Endpoint],
    tools: Mapping[str, AllowedTool],
    domain_name: str,
) -> list[PlannedTest]:
    if not proposed:
        raise LlmOutputRejectedError("El plan propuesto está vacío.")
    if len(proposed) > MAX_PLANNED_TESTS:
        raise LlmOutputRejectedError("El plan propuesto excede el máximo de pruebas.")
    plan: dict[str, PlannedTest] = {}
    for item in proposed:
        endpoint = endpoints.get(item.endpoint_id)
        if endpoint is None or not endpoint.whitelisted or not endpoint.in_scope:
            raise LlmOutputRejectedError(
                "El plan incluye un endpoint que no está en la lista blanca."
            )
        tool = tools.get(item.tool)
        if tool is None or not tool.active:
            raise LlmOutputRejectedError("El plan incluye una herramienta que no está permitida.")
        try:
            ensure_url_in_scope(endpoint.url, domain_name)
            effective_params(tool.name, item.params, tool.allowed_params)
        except (OutOfScopeError, ToolNotAllowedError) as exc:
            raise LlmOutputRejectedError(
                f"El plan incluye parámetros no permitidos: {exc.message}"
            ) from exc
        if tool.name == "testssl" and urlsplit(endpoint.url).scheme != "https":
            raise LlmOutputRejectedError("testssl solo se puede aplicar a endpoints https.")
        key = json.dumps(
            [str(item.endpoint_id), tool.name, item.params], sort_keys=True, default=str
        )
        plan.setdefault(key, PlannedTest(item.endpoint_id, tool.name, dict(item.params)))
    return list(plan.values())
