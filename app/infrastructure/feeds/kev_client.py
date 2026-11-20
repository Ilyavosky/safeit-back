import time
from collections.abc import Callable

from app.domain.errors import FeedUnavailableError
from app.infrastructure.feeds.http import RetryingJsonClient

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_SECONDS = 3600.0


class KevClient:
    def __init__(
        self,
        http: RetryingJsonClient,
        *,
        url: str = KEV_URL,
        clock: Callable[[], float] = time.monotonic,
        cache_seconds: float = CACHE_SECONDS,
    ) -> None:
        self._http = http
        self._url = url
        self._clock = clock
        self._cache_seconds = cache_seconds
        self._cached: set[str] | None = None
        self._cached_at = 0.0

    async def list_cve_ids(self) -> set[str]:
        now = self._clock()
        if self._cached is not None and now - self._cached_at < self._cache_seconds:
            return set(self._cached)
        data = await self._http.get_json(self._url)
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise FeedUnavailableError
        ids = {
            str(item["cveID"]).strip().upper()
            for item in data["vulnerabilities"]
            if isinstance(item, dict) and "cveID" in item
        }
        self._cached, self._cached_at = ids, now
        return set(ids)
