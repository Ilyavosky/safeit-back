import hashlib
import json
from dataclasses import asdict, is_dataclass
from typing import Any
from uuid import UUID, uuid4

from app.application.llm_budget import TokenBudget
from app.application.ports.clock import Clock
from app.application.ports.llm import LlmDecisionRepository, LlmResponse
from app.domain.entities.llm_decision import LlmDecision
from app.domain.value_objects.llm_kind import LlmKind

MAX_RAW_CHARS = 20000


def input_hash(kind: LlmKind, request: Any) -> str:
    payload = (
        asdict(request) if is_dataclass(request) and not isinstance(request, type) else request
    )
    canonical = json.dumps({"kind": kind.value, "input": payload}, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DecisionRecorder:
    def __init__(self, decisions: LlmDecisionRepository, budget: TokenBudget, clock: Clock) -> None:
        self._decisions = decisions
        self._budget = budget
        self._clock = clock

    async def record(
        self,
        scan_id: UUID,
        kind: LlmKind,
        request: Any,
        response: LlmResponse[Any],
        *,
        validated: bool,
        justification: str | None,
    ) -> LlmDecision:
        self._budget.spend(scan_id, response.tokens)
        decision = LlmDecision(
            id=uuid4(),
            scan_id=scan_id,
            kind=kind,
            model=response.model[:100],
            input_hash=input_hash(kind, request),
            output=_as_object(response.raw),
            validated=validated,
            justification=justification[:1000] if justification else None,
            created_at=self._clock.now(),
        )
        await self._decisions.add(decision)
        return decision


def _as_object(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    return {"raw": json.dumps(raw, default=str)[:MAX_RAW_CHARS]}
