from collections.abc import Mapping
from typing import Any

from app.domain.errors import OutOfScopeError, ToolNotAllowedError

MAX_RATE_LIMIT = 50
MAX_TIMEOUT_SECONDS = 900
DEFAULT_TIMEOUT_SECONDS = 300
FIXED_TOOLS = frozenset({"testssl", "headers"})


def effective_params(
    tool_name: str, requested: Mapping[str, Any], allowed: Mapping[str, Any]
) -> dict[str, Any]:
    timeout = _bounded_int(allowed.get("timeout_s"), DEFAULT_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS)
    if tool_name in FIXED_TOOLS:
        if requested:
            raise OutOfScopeError(f"{tool_name} no acepta parámetros.")
        return {"timeout_s": timeout}
    if tool_name == "nuclei":
        return _nuclei_params(requested, allowed, timeout)
    raise ToolNotAllowedError(tool_name)


def _nuclei_params(
    requested: Mapping[str, Any], allowed: Mapping[str, Any], timeout: int
) -> dict[str, Any]:
    unknown = set(requested) - {"tags", "rate_limit"}
    if unknown:
        raise OutOfScopeError("nuclei no acepta los parámetros solicitados.")
    allow = {str(tag).lower() for tag in allowed.get("tags_allowlist", [])}
    deny = {str(tag).lower() for tag in allowed.get("tags_denylist", [])}
    tags = {str(tag).strip().lower() for tag in requested.get("tags", allow)}
    if not tags or tags & deny or not tags <= allow:
        raise OutOfScopeError("Las etiquetas de nuclei solicitadas no están permitidas.")
    cap = _bounded_int(allowed.get("rate_limit"), MAX_RATE_LIMIT, MAX_RATE_LIMIT)
    asked = requested.get("rate_limit", cap)
    if not isinstance(asked, int) or isinstance(asked, bool) or asked < 1:
        raise OutOfScopeError("La tasa de nuclei solicitada no es válida.")
    return {
        "tags": sorted(tags),
        "tags_denylist": sorted(deny),
        "rate_limit": min(asked, cap),
        "timeout_s": timeout,
    }


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return default
    return min(value, maximum)
