import re
from collections.abc import Sequence

from app.domain.services.network_safety import is_public_address

_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
MAX_HOSTNAME_LENGTH = 253


def normalize_host(raw: str) -> str | None:
    host = raw.strip().lower().rstrip(".")
    if not host or len(host) > MAX_HOSTNAME_LENGTH or host.startswith("*."):
        return None
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels):
        return None
    return host


def discard_reason(addresses: Sequence[str]) -> str | None:
    if not addresses:
        return "unresolved"
    if not all(is_public_address(address) for address in addresses):
        return "address_not_public"
    return None
