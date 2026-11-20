import httpx
import structlog

from app.domain.services.recon_scope import normalize_host
from app.domain.services.scope_policy import is_host_in_domain

log = structlog.get_logger(__name__)

MAX_BODY_BYTES = 8_000_000
MAX_NAMES = 500
USER_AGENT = "SafeIT-PublicAnalysis/1.0"


class CrtShSource:
    def __init__(
        self,
        *,
        base_url: str = "https://crt.sh",
        timeout: float = 25.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._transport = transport

    async def subdomains(self, domain: str) -> list[str]:
        params = {"q": f"%.{domain}", "output": "json"}
        try:
            async with (
                httpx.AsyncClient(
                    timeout=self._timeout,
                    transport=self._transport,
                    headers={"User-Agent": USER_AGENT},
                ) as client,
                client.stream("GET", f"{self._base_url}/", params=params) as response,
            ):
                if response.status_code != 200:
                    log.info("crtsh_unavailable", status=response.status_code)
                    return []
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_BODY_BYTES:
                        return []
            rows = httpx.Response(200, content=bytes(body)).json()
        except (httpx.HTTPError, ValueError) as exc:
            log.info("crtsh_failed", reason=type(exc).__name__)
            return []
        return _names(rows, domain)


def _names(rows: object, domain: str) -> list[str]:
    found: dict[str, None] = {}
    if not isinstance(rows, list):
        return []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for line in str(row.get("name_value", "")).splitlines():
            host = normalize_host(line.strip().removeprefix("*."))
            if host is not None and is_host_in_domain(host, domain):
                found[host] = None
            if len(found) >= MAX_NAMES:
                return list(found)
    return list(found)
