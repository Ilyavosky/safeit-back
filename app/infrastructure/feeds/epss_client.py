from collections.abc import Sequence

from app.domain.errors import FeedUnavailableError
from app.infrastructure.feeds.http import RetryingJsonClient

EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100


class EpssClient:
    def __init__(self, http: RetryingJsonClient, base_url: str = EPSS_URL) -> None:
        self._http = http
        self._base_url = base_url

    async def get_scores(self, cve_ids: Sequence[str]) -> dict[str, float]:
        scores: dict[str, float] = {}
        for start in range(0, len(cve_ids), BATCH_SIZE):
            batch = cve_ids[start : start + BATCH_SIZE]
            data = await self._http.get_json(f"{self._base_url}?cve={','.join(batch)}")
            if not isinstance(data, dict) or not isinstance(data.get("data"), list):
                raise FeedUnavailableError
            for row in data["data"]:
                try:
                    scores[str(row["cve"]).upper()] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
        return scores
