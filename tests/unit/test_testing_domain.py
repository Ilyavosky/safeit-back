from uuid import uuid4

import pytest

from app.domain.entities.endpoint import Endpoint
from app.domain.errors import OutOfScopeError, ToolNotAllowedError
from app.domain.services.finding_priority import finding_priority
from app.domain.services.header_analysis import analyze_headers
from app.domain.services.scope_policy import ensure_url_in_scope, is_host_in_domain
from app.domain.services.test_planning import plan_tests
from app.domain.services.tool_policy import effective_params
from app.domain.value_objects.severity import Severity

NUCLEI_POLICY = {
    "tags_allowlist": ["cve", "misconfig", "exposure", "tech"],
    "tags_denylist": ["dos", "intrusive", "fuzz", "bruteforce"],
    "rate_limit": 50,
    "timeout_s": 600,
}


def _endpoint(url: str) -> Endpoint:
    return Endpoint(uuid4(), uuid4(), uuid4(), url, 200, (), True, True)


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://example.com", "example.com"),
        ("http://WWW.Example.com:8080/a?b=1", "www.example.com"),
        ("https://a.b.example.com./x", "a.b.example.com"),
    ],
)
def test_scope_accepts_the_domain_and_its_subdomains(url: str, host: str) -> None:
    assert ensure_url_in_scope(url, "example.com") == host


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.com",
        "https://example.com.evil.com",
        "https://notexample.com",
        "https://127.0.0.1/example.com",
        "https://example.com@evil.com",
        "https://user:pass@example.com",
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "example.com",
        "https://",
        "https://example.com:notaport",
    ],
)
def test_scope_rejects_everything_else(url: str) -> None:
    with pytest.raises(OutOfScopeError):
        ensure_url_in_scope(url, "example.com")


def test_host_in_domain_requires_a_label_boundary() -> None:
    assert is_host_in_domain("api.example.com", "example.com")
    assert not is_host_in_domain("badexample.com", "example.com")


def test_plan_covers_every_endpoint_and_tests_tls_once_per_host() -> None:
    https_a = _endpoint("https://example.com/")
    https_b = _endpoint("https://example.com/login")
    plain = _endpoint("http://old.example.com/")
    plan = plan_tests([https_b, plain, https_a])
    pairs = [(p.endpoint_id, p.tool_name) for p in plan]
    assert pairs.count((https_a.id, "testssl")) + pairs.count((https_b.id, "testssl")) == 1
    assert all((e.id, "headers") in pairs for e in (https_a, https_b, plain))
    assert all((e.id, "nuclei") in pairs for e in (https_a, https_b, plain))
    assert not any(p.endpoint_id == plain.id and p.tool_name == "testssl" for p in plan)
    nuclei = next(p for p in plan if p.tool_name == "nuclei")
    assert nuclei.params == {"tags": ["cve", "exposure", "misconfig", "tech"]}
    assert plan_tests([]) == []
    assert plan_tests([https_a, plain]) == plan_tests([plain, https_a])


def test_tool_policy_defaults_to_the_allowlist() -> None:
    params = effective_params("nuclei", {}, NUCLEI_POLICY)
    assert params == {
        "tags": ["cve", "exposure", "misconfig", "tech"],
        "tags_denylist": ["bruteforce", "dos", "fuzz", "intrusive"],
        "rate_limit": 50,
        "timeout_s": 600,
    }


@pytest.mark.parametrize(
    "requested",
    [
        {"tags": ["dos"]},
        {"tags": ["cve", "intrusive"]},
        {"tags": ["rce"]},
        {"tags": []},
        {"rate_limit": 0},
        {"rate_limit": "fast"},
        {"rate_limit": True},
        {"args": ["-t", "/etc"]},
    ],
)
def test_tool_policy_rejects_forbidden_nuclei_params(requested: dict[str, object]) -> None:
    with pytest.raises(OutOfScopeError):
        effective_params("nuclei", requested, NUCLEI_POLICY)


def test_tool_policy_caps_rate_and_timeout() -> None:
    params = effective_params(
        "nuclei", {"rate_limit": 5000}, {**NUCLEI_POLICY, "rate_limit": 500, "timeout_s": 99999}
    )
    assert (params["rate_limit"], params["timeout_s"]) == (50, 900)
    assert effective_params("nuclei", {"rate_limit": 10}, NUCLEI_POLICY)["rate_limit"] == 10


def test_tool_policy_fixed_tools_and_unknown_tools() -> None:
    assert effective_params("headers", {}, {"timeout_s": 30}) == {"timeout_s": 30}
    assert effective_params("testssl", {}, {}) == {"timeout_s": 300}
    with pytest.raises(OutOfScopeError):
        effective_params("headers", {"x": 1}, {})
    with pytest.raises(ToolNotAllowedError):
        effective_params("sqlmap", {}, {})


def test_finding_priority_prefers_cve_data_over_the_baseline() -> None:
    assert finding_priority(Severity.HIGH, []) == 70.0
    assert finding_priority(Severity.HIGH, [52.0, 91.4]) == 91.4
    assert finding_priority(Severity.INFO, []) == 5.0


HARDENED = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax"),
]


def _titles(url: str, headers: list[tuple[str, str]]) -> list[str]:
    return [f.title for f in analyze_headers(url, headers)]


def test_hardened_response_has_no_findings() -> None:
    assert analyze_headers("https://example.com/", HARDENED) == []


def test_bare_https_response_reports_every_missing_header() -> None:
    findings = analyze_headers("https://example.com/", [("Server", "nginx")])
    assert {f.title: f.severity for f in findings} == {
        "Falta la cabecera Strict-Transport-Security (HSTS)": Severity.MEDIUM,
        "Falta la cabecera Content-Security-Policy": Severity.MEDIUM,
        "Falta la cabecera X-Frame-Options": Severity.LOW,
        "Falta la cabecera X-Content-Type-Options: nosniff": Severity.LOW,
        "Falta la cabecera Referrer-Policy": Severity.INFO,
    }


def test_http_endpoint_does_not_require_hsts_or_secure_cookies() -> None:
    titles = _titles("http://example.com/", [("Set-Cookie", "sid=abc; HttpOnly")])
    assert "Falta la cabecera Strict-Transport-Security (HSTS)" not in titles
    assert not any("sin Secure" in t for t in titles)


def test_frame_ancestors_replaces_x_frame_options() -> None:
    headers = [h for h in HARDENED if h[0] != "X-Frame-Options"]
    headers[1] = ("Content-Security-Policy", "frame-ancestors 'none'")
    assert analyze_headers("https://example.com/", headers) == []


def test_short_hsts_and_insecure_cookies_are_reported_without_leaking_values() -> None:
    headers = [h for h in HARDENED if h[0] not in {"Strict-Transport-Security", "Set-Cookie"}]
    headers += [
        ("strict-transport-security", "max-age=300"),
        ("Set-Cookie", "session=TOP-SECRET-VALUE; Path=/"),
        ("Set-Cookie", "ok=1; Secure; HttpOnly"),
    ]
    findings = analyze_headers("https://example.com/", headers)
    assert [f.title for f in findings] == [
        "HSTS con vigencia corta",
        "Cookie sin Secure: session",
        "Cookie sin HttpOnly: session",
    ]
    assert all("TOP-SECRET-VALUE" not in f.evidence for f in findings)
