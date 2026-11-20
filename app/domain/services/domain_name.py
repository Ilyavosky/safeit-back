import re

from app.domain.errors import InvalidDomainNameError

MAX_DOMAIN_LENGTH = 253

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"(?:{_LABEL}\.)+[a-z]{{2,63}}")


def normalize_domain_name(raw: str) -> str:
    name = raw.strip().lower().removesuffix(".")
    if len(name) > MAX_DOMAIN_LENGTH or _DOMAIN.fullmatch(name) is None:
        raise InvalidDomainNameError
    return name
