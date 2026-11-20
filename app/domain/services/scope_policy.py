from urllib.parse import urlsplit

from app.domain.errors import OutOfScopeError

ALLOWED_SCHEMES = frozenset({"http", "https"})


def target_host(url: str) -> str:
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018
    except ValueError as exc:
        raise OutOfScopeError("La URL del objetivo no es válida.") from exc
    if parts.scheme not in ALLOWED_SCHEMES or not host:
        raise OutOfScopeError("Solo se permiten URL http o https.")
    if parts.username is not None or parts.password is not None:
        raise OutOfScopeError("La URL del objetivo no puede incluir credenciales.")
    return host.lower().rstrip(".")


def is_host_in_domain(host: str, domain_name: str) -> bool:
    candidate = host.lower().rstrip(".")
    return candidate == domain_name or candidate.endswith(f".{domain_name}")


def ensure_url_in_scope(url: str, domain_name: str) -> str:
    host = target_host(url)
    if not is_host_in_domain(host, domain_name):
        raise OutOfScopeError
    return host
