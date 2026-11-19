import json
import time
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

import httpx
import structlog
from pydantic import BaseModel, ValidationError

from app.application.ports.llm import (
    LlmResponse,
    PlanRequest,
    ReportRequest,
    ReviewRequest,
)
from app.domain.entities.llm_proposals import (
    CorrelationProposal,
    FalsePositiveProposal,
    PlanProposal,
    ReportDraft,
)
from app.domain.errors_llm import LlmUnavailableError
from app.infrastructure.llm.prompts import load_prompt
from app.infrastructure.llm.schemas import CorrelationOut, FalsePositiveOut, PlanOut, ReportOut
from app.infrastructure.llm.untrusted_data import wrap_untrusted

log = structlog.get_logger(__name__)

_Output = BaseModel
API_VERSION = "2023-06-01"
MAX_OUTPUT_TOKENS = 4096


class HttpLlmGateway:
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.anthropic.com",
        timeout_s: float = 60.0,
        max_seconds: float = 120.0,
        transport: httpx.AsyncBaseTransport | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_s
        self._max_seconds = max_seconds
        self._transport = transport
        self._monotonic = monotonic

    @property
    def model(self) -> str:
        return self._model

    async def plan(self, request: PlanRequest) -> LlmResponse[PlanProposal]:
        return await self._run("plan", request, PlanOut, PlanOut.to_domain)

    async def correlate(self, request: ReviewRequest) -> LlmResponse[CorrelationProposal]:
        return await self._run("correlation", request, CorrelationOut, CorrelationOut.to_domain)

    async def review_false_positives(
        self, request: ReviewRequest
    ) -> LlmResponse[FalsePositiveProposal]:
        return await self._run(
            "false_positive", request, FalsePositiveOut, FalsePositiveOut.to_domain
        )

    async def report(self, request: ReportRequest) -> LlmResponse[ReportDraft]:
        return await self._run("report", request, ReportOut, ReportOut.to_domain)

    async def _run[M: _Output, T](
        self, prompt: str, request: Any, schema: type[M], convert: Callable[[M], T]
    ) -> LlmResponse[T]:
        system = f"{load_prompt('_preamble')}\n\n{load_prompt(prompt)}"
        user = wrap_untrusted(asdict(request))
        messages: list[dict[str, str]] = [{"role": "user", "content": user}]
        started = self._monotonic()
        tokens = 0
        text = ""
        error = "sin respuesta"
        for attempt in range(2):
            if attempt and self._monotonic() - started > self._max_seconds:
                break
            text, used = await self._call(system, messages)
            tokens += used
            try:
                parsed = schema.model_validate(_extract_json(text))
            except (ValueError, ValidationError) as exc:
                error = f"salida inválida: {str(exc)[:300]}"
                messages = [
                    *messages[:1],
                    {"role": "assistant", "content": text[:4000]},
                    {
                        "role": "user",
                        "content": f"Esquema incumplido ({error}). Responde solo con el JSON.",
                    },
                ]
                continue
            return LlmResponse(
                self._model,
                tokens,
                parsed.model_dump(mode="json"),
                convert(parsed),
                None,
            )
        return LlmResponse(self._model, tokens, {"raw": text[:4000]}, None, error)

    async def _call(self, system: str, messages: list[dict[str, str]]) -> tuple[str, int]:
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport
            ) as client:
                response = await client.post(
                    f"{self._base_url}/v1/messages",
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": API_VERSION,
                        "content-type": "application/json",
                    },
                    json={
                        "model": self._model,
                        "max_tokens": MAX_OUTPUT_TOKENS,
                        "temperature": 0,
                        "system": system,
                        "messages": messages,
                    },
                )
        except httpx.HTTPError as exc:
            raise LlmUnavailableError(f"Fallo de red: {type(exc).__name__}") from exc
        if response.status_code != 200:
            raise LlmUnavailableError(f"El proveedor respondió {response.status_code}.")
        try:
            body = response.json()
            text = "".join(b.get("text", "") for b in body["content"] if b.get("type") == "text")
            usage = body.get("usage", {})
            tokens = int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise LlmUnavailableError("Respuesta del proveedor ilegible.") from exc
        return text, tokens


def _extract_json(text: str) -> Any:
    stripped = text.strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no hay objeto JSON")
    return json.loads(stripped[start : end + 1])
