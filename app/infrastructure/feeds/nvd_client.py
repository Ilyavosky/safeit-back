from collections.abc import AsyncIterator
from typing import Any

from app.application.ports.cve_catalog import NvdCve
from app.domain.errors import FeedUnavailableError, InvalidCveIdError
from app.domain.services.cve_id import normalize_cve_id
from app.infrastructure.feeds.http import MinIntervalLimiter, RetryingJsonClient

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
MAX_PAGES = 20
INTERVAL_WITHOUT_KEY = 6.0
INTERVAL_WITH_KEY = 0.7
METRIC_ORDER = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")


class NvdClient:
    def __init__(
        self,
        http: RetryingJsonClient,
        *,
        api_key: str | None = None,
        limiter: MinIntervalLimiter | None = None,
        base_url: str = NVD_URL,
    ) -> None:
        self._http = http
        self._headers = {"apiKey": api_key} if api_key else {}
        interval = INTERVAL_WITH_KEY if api_key else INTERVAL_WITHOUT_KEY
        self._limiter = limiter or MinIntervalLimiter(interval)
        self._base_url = base_url

    async def iter_kev_cves(self) -> AsyncIterator[NvdCve]:
        start = 0
        for _ in range(MAX_PAGES):
            page = await self._get(
                f"{self._base_url}?hasKev&resultsPerPage={PAGE_SIZE}&startIndex={start}"
            )
            items = page.get("vulnerabilities", [])
            for item in items:
                parsed = _parse_cve(item)
                if parsed is not None:
                    yield parsed
            start += len(items)
            if not items or start >= int(page.get("totalResults", 0)):
                return

    async def get_cve(self, cve_id: str) -> NvdCve | None:
        page = await self._get(f"{self._base_url}?cveId={normalize_cve_id(cve_id)}")
        for item in page.get("vulnerabilities", []):
            parsed = _parse_cve(item)
            if parsed is not None:
                return parsed
        return None

    async def _get(self, url: str) -> dict[str, Any]:
        await self._limiter.wait()
        data = await self._http.get_json(url, headers=self._headers)
        if not isinstance(data, dict):
            raise FeedUnavailableError
        return data


def _parse_cve(item: Any) -> NvdCve | None:
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
        return None
    try:
        cve_id = normalize_cve_id(cve["id"])
    except InvalidCveIdError:
        return None
    score, vector = _best_cvss(cve.get("metrics") or {})
    return NvdCve(cve_id=cve_id, cvss_score=score, cvss_vector=vector)


def _best_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in METRIC_ORDER:
        entries = metrics.get(key) or []
        ordered = sorted(entries, key=lambda e: e.get("type") != "Primary")
        for entry in ordered:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, int | float) and 0 <= score <= 10:
                vector = data.get("vectorString")
                return float(score), vector[:128] if isinstance(vector, str) else None
    return None, None
