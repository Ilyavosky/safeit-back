from app.application.ports.clock import Clock


class InMemoryRateLimiter:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._hits: dict[str, list[float]] = {}

    async def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = self._clock.now().timestamp()
        threshold = now - window_seconds
        recent = [stamp for stamp in self._hits.get(key, []) if stamp > threshold]
        if len(recent) >= limit:
            self._hits[key] = recent
            return False
        recent.append(now)
        self._hits[key] = recent
        self._prune(threshold)
        return True

    def _prune(self, threshold: float) -> None:
        if len(self._hits) < 10_000:
            return
        for key in [k for k, stamps in self._hits.items() if not stamps or stamps[-1] <= threshold]:
            del self._hits[key]
