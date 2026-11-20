import pytest

from app.domain.errors import InvalidDomainNameError, PublicTargetNotAllowedError
from app.domain.services.public_classifier import (
    classify_host,
    detect_provider,
    security_headers_present,
    strip_version,
    technologies_from,
)
from app.domain.services.public_scope import normalize_public_target
from app.domain.value_objects.host_kind import HostKind


@pytest.mark.parametrize(
    "raw", ["agencia.gov", "base.mil", "algo.local", "app.internal", "x.test", "dep.gov.mx"]
)
def test_blocked_targets_are_rejected(raw: str) -> None:
    with pytest.raises(PublicTargetNotAllowedError):
        normalize_public_target(raw)


def test_protected_domains_and_their_subdomains_are_rejected() -> None:
    protected = frozenset({"safeit.app"})

    with pytest.raises(PublicTargetNotAllowedError):
        normalize_public_target("safeit.app", protected)
    with pytest.raises(PublicTargetNotAllowedError):
        normalize_public_target("api.safeit.app", protected)


def test_valid_target_is_normalized() -> None:
    assert normalize_public_target("  Ejemplo.COM. ") == "ejemplo.com"


@pytest.mark.parametrize("raw", ["10.0.0.1", "localhost", "http://x.com", "a b.com"])
def test_ips_and_malformed_names_are_rejected(raw: str) -> None:
    with pytest.raises((InvalidDomainNameError, PublicTargetNotAllowedError)):
        normalize_public_target(raw)


def _classify(host: str, **overrides: object) -> HostKind:
    values: dict[str, object] = {
        "http_status": 200,
        "title": None,
        "technologies": (),
        "content_type": "text/html",
        "redirect_host": None,
    }
    values.update(overrides)
    return classify_host(host, "ejemplo.com", **values)  # type: ignore[arg-type]


def test_classification_rules() -> None:
    assert _classify("api.ejemplo.com") == HostKind.API
    assert _classify("x.ejemplo.com", content_type="application/json") == HostKind.API
    assert _classify("docs.ejemplo.com") == HostKind.DOCS
    assert _classify("blog.ejemplo.com") == HostKind.BLOG
    assert _classify("x.ejemplo.com", technologies=("WordPress",)) == HostKind.BLOG
    assert _classify("sso.ejemplo.com") == HostKind.LOGIN_PANEL
    assert _classify("x.ejemplo.com", title="Iniciar sesión") == HostKind.LOGIN_PANEL
    assert _classify("ejemplo.com") == HostKind.WEB_APP
    assert _classify("old.ejemplo.com", http_status=301, redirect_host="ejemplo.com") == (
        HostKind.REDIRECT
    )
    assert _classify("viejo.ejemplo.com", http_status=None) == HostKind.NO_SERVICE
    assert _classify("mail.ejemplo.com", http_status=None) == HostKind.MAIL


def test_provider_from_headers_then_cnames() -> None:
    assert detect_provider({"CF-Ray": "abc"}, []) == "Cloudflare"
    assert detect_provider({}, ["d111.cloudfront.net."]) == "Amazon CloudFront"
    assert detect_provider({}, ["algo.desconocido.net"]) is None


def test_versions_are_never_exposed() -> None:
    assert strip_version("nginx/1.18.0") == "nginx"
    assert strip_version("Apache/2.4.41 (Ubuntu)") == "Apache"
    assert technologies_from({"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.2.1"}, "") == (
        "nginx",
        "PHP",
    )
    html = '<meta name="generator" content="WordPress 6.4.2">'
    assert technologies_from({}, html) == ("WordPress",)


def test_security_headers_are_reported_by_name() -> None:
    present = security_headers_present({"Strict-Transport-Security": "x", "X-Other": "y"})

    assert present == ("HSTS",)
