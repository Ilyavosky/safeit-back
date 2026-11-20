import re
from collections.abc import Mapping, Sequence

from app.domain.value_objects.host_kind import HostKind

_API_LABELS = {"api", "graphql", "rest", "gateway", "ws", "grpc"}
_MAIL_LABELS = {"mail", "smtp", "imap", "pop", "pop3", "mx", "webmail", "email", "mta"}
_DOCS_LABELS = {"docs", "doc", "developer", "developers", "help", "support", "wiki", "kb"}
_BLOG_LABELS = {"blog", "news", "press", "noticias"}
_LOGIN_LABELS = {"login", "sso", "auth", "accounts", "id", "signin", "portal", "admin"}
_LOGIN_TITLE = re.compile(
    r"\b(log ?in|sign ?in|iniciar sesi[oó]n|acceso|admin(istrat)?)\b", re.IGNORECASE
)
_DOCS_TITLE = re.compile(r"\b(documentation|documentaci[oó]n|api reference|docs)\b", re.IGNORECASE)
_BLOG_TECH = {"wordpress", "ghost", "medium", "hugo", "jekyll"}
_JSON_TYPES = ("application/json", "application/problem+json")


def classify_host(
    host: str,
    domain: str,
    *,
    http_status: int | None,
    title: str | None,
    technologies: Sequence[str],
    content_type: str | None,
    redirect_host: str | None,
    mail_hosts: Sequence[str] = (),
) -> HostKind:
    first_label = host.removesuffix(f".{domain}").split(".")[0] if host != domain else ""
    is_mail_host = host in mail_hosts or first_label in _MAIL_LABELS
    if http_status is None:
        return HostKind.MAIL if is_mail_host else HostKind.NO_SERVICE
    if redirect_host is not None and redirect_host != host and 300 <= http_status < 400:
        return HostKind.REDIRECT
    lowered_tech = {t.lower() for t in technologies}
    if first_label in _API_LABELS or (content_type or "").lower().startswith(_JSON_TYPES):
        return HostKind.API
    if is_mail_host:
        return HostKind.MAIL
    if first_label in _DOCS_LABELS or (title and _DOCS_TITLE.search(title)):
        return HostKind.DOCS
    if first_label in _BLOG_LABELS or lowered_tech & _BLOG_TECH:
        return HostKind.BLOG
    if first_label in _LOGIN_LABELS or (title and _LOGIN_TITLE.search(title)):
        return HostKind.LOGIN_PANEL
    return HostKind.WEB_APP


_PROVIDER_CNAMES: Mapping[str, str] = {
    "cloudfront.net": "Amazon CloudFront",
    "amazonaws.com": "Amazon Web Services",
    "elasticbeanstalk.com": "Amazon Web Services",
    "vercel-dns.com": "Vercel",
    "vercel.app": "Vercel",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "azurewebsites.net": "Microsoft Azure",
    "azureedge.net": "Microsoft Azure",
    "trafficmanager.net": "Microsoft Azure",
    "cloudflare.net": "Cloudflare",
    "fastly.net": "Fastly",
    "akamaiedge.net": "Akamai",
    "edgekey.net": "Akamai",
    "googleusercontent.com": "Google Cloud",
    "appspot.com": "Google Cloud",
    "run.app": "Google Cloud",
    "railway.app": "Railway",
    "fly.dev": "Fly.io",
    "pages.dev": "Cloudflare",
    "wixdns.net": "Wix",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "squarespace.com": "Squarespace",
}
_PROVIDER_HEADERS: Mapping[str, str] = {
    "cf-ray": "Cloudflare",
    "x-vercel-id": "Vercel",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-nf-request-id": "Netlify",
    "fly-request-id": "Fly.io",
    "x-github-request-id": "GitHub Pages",
    "x-azure-ref": "Microsoft Azure",
    "x-served-by": "Fastly",
    "x-akamai-transformed": "Akamai",
    "x-shopify-stage": "Shopify",
}


def detect_provider(headers: Mapping[str, str], cnames: Sequence[str]) -> str | None:
    lowered = {k.lower(): v for k, v in headers.items()}
    for header, provider in _PROVIDER_HEADERS.items():
        if header in lowered:
            return provider
    for cname in cnames:
        target = cname.lower().rstrip(".")
        for suffix, provider in _PROVIDER_CNAMES.items():
            if target == suffix or target.endswith(f".{suffix}"):
                return provider
    server = lowered.get("server", "").lower()
    if "cloudflare" in server:
        return "Cloudflare"
    if "awselb" in server or "amazons3" in server:
        return "Amazon Web Services"
    return None


_VERSION_TAIL = re.compile(r"[\s/_-]*v?\d[\w.\-+]*.*$", re.IGNORECASE)
_SERVER_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9 ._-]{1,30}$")
_SECURITY_HEADER_NAMES: Mapping[str, str] = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}
_GENERATOR = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']{1,60})[\"']", re.IGNORECASE
)


def strip_version(raw: str) -> str | None:
    base = _VERSION_TAIL.sub("", raw.strip().split("(")[0]).strip()
    return base if _SERVER_TOKEN.fullmatch(base) else None


def technologies_from(headers: Mapping[str, str], html_head: str) -> tuple[str, ...]:
    lowered = {k.lower(): v for k, v in headers.items()}
    found: dict[str, None] = {}
    for header in ("server", "x-powered-by"):
        value = lowered.get(header)
        if value:
            name = strip_version(value.split(",")[0].split()[0] if " " in value else value)
            if name:
                found[name] = None
    match = _GENERATOR.search(html_head)
    if match:
        name = strip_version(match.group(1))
        if name:
            found[name] = None
    return tuple(found)


def security_headers_present(headers: Mapping[str, str]) -> tuple[str, ...]:
    lowered = {k.lower() for k in headers}
    return tuple(label for name, label in _SECURITY_HEADER_NAMES.items() if name in lowered)
