import json
import re
import secrets
from typing import Any

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_FIELD_CHARS = 1500


def sanitize(text: str, limit: int = MAX_FIELD_CHARS) -> str:
    cleaned = _CONTROL.sub("", text)
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "…[truncado]"
    return cleaned


def wrap_untrusted(payload: Any) -> str:
    boundary = secrets.token_hex(8)
    body = json.dumps(_clean(payload), ensure_ascii=False, indent=1, default=str)
    body = body.replace(boundary, "")
    return f'<datos_no_confiables id="{boundary}">\n{body}\n</datos_no_confiables id="{boundary}">'


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, dict):
        return {sanitize(str(k), 200): _clean(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_clean(v) for v in value]
    return value
