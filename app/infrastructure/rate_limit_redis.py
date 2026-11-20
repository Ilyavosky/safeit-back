import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError

log = structlog.get_logger("app.rate_limit")

KEY_PREFIX = "safeit:rl:"


class RedisRateLimiter:
    def __init__(
        self,
        client: Redis,
        fail_closed_prefixes: tuple[str, ...] = ("login:",),
    ) -> None:
        self._client = client
        self._fail_closed_prefixes = fail_closed_prefixes

    async def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        redis_key = f"{KEY_PREFIX}{key}"
        try:
            async with self._client.pipeline(transaction=True) as pipe:
                pipe.incr(redis_key)
                pipe.expire(redis_key, window_seconds, nx=True)
                count, _ = await pipe.execute()
        except RedisError:
            log.warning("rate_limit_backend_unavailable", key_prefix=key.split(":", 1)[0])
            return not key.startswith(self._fail_closed_prefixes)
        return int(count) <= limit

    async def aclose(self) -> None:
        await self._client.aclose()
