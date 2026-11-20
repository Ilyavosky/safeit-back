import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import structlog

from app.domain.errors import FeedUnavailableError

log = structlog.get_logger(__name__)

RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_RETRY_AFTER_SECONDS = 60.0

Sleep = Callable[[float], Awaitable[None]]


class RetryingJsonClient:
    def __init__(
        self,
        *,
        timeout: float = 20.0,
        max_attempts: int = 4,
        backoff_seconds: float = 1.0,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._backoff = backoff_seconds
        self._transport = transport
        self._sleep = sleep

    async def get_json(self, url: str, headers: dict[str, str] | None = None) -> Any:
        last_reason = "sin respuesta"
        for attempt in range(1, self._max_attempts + 1):
            delay = self._backoff * 2 ** (attempt - 1)
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout, transport=self._transport, follow_redirects=False
                ) as client:
                    response = await client.get(url, headers=headers)
            except httpx.TransportError as exc:
                last_reason = type(exc).__name__
            else:
                if response.status_code == 200:
                    return _parse(response)
                last_reason = f"HTTP {response.status_code}"
                if response.status_code not in RETRYABLE_STATUSES:
                    break
                delay = _retry_after(response, default=delay)
            if attempt < self._max_attempts:
                log.info("feed_retry", url=_safe_url(url), reason=last_reason, wait=delay)
                await self._sleep(delay)
        log.warning("feed_unavailable", url=_safe_url(url), reason=last_reason)
        raise FeedUnavailableError


class MinIntervalLimiter:
    def __init__(
        self,
        min_interval: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._min_interval = min_interval
        self._clock = clock
        self._sleep = sleep
        self._next_at = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = self._clock()
            if now < self._next_at:
                await self._sleep(self._next_at - now)
                now = self._next_at
            self._next_at = now + self._min_interval


def _parse(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError as exc:
        log.warning("feed_invalid_json", url=_safe_url(str(response.url)))
        raise FeedUnavailableError from exc


def _retry_after(response: httpx.Response, default: float) -> float:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return default
    try:
        return max(0.0, min(float(raw), MAX_RETRY_AFTER_SECONDS))
    except ValueError:
        return default


def _safe_url(url: str) -> str:
    return url.split("?", 1)[0]
