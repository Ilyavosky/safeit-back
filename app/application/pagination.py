import base64
import binascii
import json
from uuid import UUID

from app.domain.errors import InvalidCursorError

DEFAULT_LIMIT = 25
MAX_LIMIT = 100


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    return max(1, min(limit, MAX_LIMIT))


def encode_cursor(key: str, item_id: UUID) -> str:
    raw = json.dumps([key, str(item_id)]).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_cursor(cursor: str) -> tuple[str, UUID]:
    try:
        key, item_id = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
        if not isinstance(key, str):
            raise TypeError
        return key, UUID(item_id)
    except (binascii.Error, ValueError, TypeError, UnicodeError) as exc:
        raise InvalidCursorError from exc
