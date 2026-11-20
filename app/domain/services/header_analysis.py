from collections.abc import Sequence

from app.domain.entities.raw_finding import RawFinding
from app.domain.value_objects.severity import Severity

MIN_HSTS_MAX_AGE = 15_552_000


def analyze_headers(url: str, headers: Sequence[tuple[str, str]]) -> list[RawFinding]:
    https = url.lower().startswith("https://")
    values: dict[str, str] = {}
    cookies: list[str] = []
    for name, value in headers:
        key = name.strip().lower()
        if key == "set-cookie":
            cookies.append(value)
        else:
            values.setdefault(key, value.strip())

    findings: list[RawFinding] = []
    csp = values.get("content-security-policy")

    if https:
        hsts = values.get("strict-transport-security")
        if hsts is None:
            findings.append(_missing("Strict-Transport-Security (HSTS)", Severity.MEDIUM, url))
        elif _hsts_max_age(hsts) < MIN_HSTS_MAX_AGE:
            findings.append(
                RawFinding(
                    "HSTS con vigencia corta",
                    Severity.LOW,
                    f"Strict-Transport-Security: {hsts[:200]} en {url}. "
                    f"Se recomienda max-age de al menos {MIN_HSTS_MAX_AGE} segundos.",
                )
            )
    if csp is None:
        findings.append(_missing("Content-Security-Policy", Severity.MEDIUM, url))
    if "x-frame-options" not in values and not (csp and "frame-ancestors" in csp.lower()):
        findings.append(_missing("X-Frame-Options", Severity.LOW, url))
    if values.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(_missing("X-Content-Type-Options: nosniff", Severity.LOW, url))
    if "referrer-policy" not in values:
        findings.append(_missing("Referrer-Policy", Severity.INFO, url))

    for cookie in cookies:
        findings.extend(_cookie_findings(cookie, https, url))
    return findings


def _missing(header: str, severity: Severity, url: str) -> RawFinding:
    return RawFinding(
        f"Falta la cabecera {header}",
        severity,
        f"La respuesta de {url} no incluye {header}.",
    )


def _hsts_max_age(value: str) -> int:
    for part in value.split(";"):
        key, _, raw = part.strip().partition("=")
        if key.lower() == "max-age":
            try:
                return int(raw.strip().strip('"'))
            except ValueError:
                return 0
    return 0


def _cookie_findings(cookie: str, https: bool, url: str) -> list[RawFinding]:
    parts = [part.strip() for part in cookie.split(";")]
    name = parts[0].partition("=")[0].strip()[:100] or "(sin nombre)"
    attributes = {part.partition("=")[0].strip().lower() for part in parts[1:]}
    findings: list[RawFinding] = []
    if https and "secure" not in attributes:
        findings.append(
            RawFinding(
                f"Cookie sin Secure: {name}",
                Severity.MEDIUM,
                f"La cookie {name} de {url} se envía sin el atributo Secure.",
            )
        )
    if "httponly" not in attributes:
        findings.append(
            RawFinding(
                f"Cookie sin HttpOnly: {name}",
                Severity.LOW,
                f"La cookie {name} de {url} es accesible desde JavaScript (sin HttpOnly).",
            )
        )
    return findings
