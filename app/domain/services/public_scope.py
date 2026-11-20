from app.domain.errors import PublicTargetNotAllowedError
from app.domain.services.domain_name import normalize_domain_name

BLOCKED_SUFFIXES = (
    "gov",
    "mil",
    "int",
    "local",
    "localhost",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "test",
    "invalid",
    "example",
    "onion",
)
MAX_PUBLIC_HOSTS = 50


def normalize_public_target(raw: str, protected_domains: frozenset[str] = frozenset()) -> str:
    name = normalize_domain_name(raw)
    labels = name.split(".")
    if labels[-1] in BLOCKED_SUFFIXES or (len(labels) > 2 and labels[-2] in {"gov", "mil"}):
        raise PublicTargetNotAllowedError
    if any(name == p or name.endswith(f".{p}") for p in protected_domains):
        raise PublicTargetNotAllowedError
    if all(label.isdigit() for label in labels):
        raise PublicTargetNotAllowedError
    return name
