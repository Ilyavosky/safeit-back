import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.infrastructure.rate_limit_redis import RedisRateLimiter


class FakePipeline:
    def __init__(self, store: dict[str, int], fail: bool) -> None:
        self._store = store
        self._fail = fail
        self._ops: list[tuple[str, str]] = []

    async def __aenter__(self) -> "FakePipeline":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    def incr(self, key: str) -> None:
        self._ops.append(("incr", key))

    def expire(self, key: str, seconds: int, nx: bool = False) -> None:
        self._ops.append(("expire", key))

    async def execute(self) -> list[int]:
        if self._fail:
            raise RedisConnectionError("down")
        results = []
        for op, key in self._ops:
            if op == "incr":
                self._store[key] = self._store.get(key, 0) + 1
                results.append(self._store[key])
            else:
                results.append(1)
        return results


class FakeRedis:
    def __init__(self, fail: bool = False) -> None:
        self.store: dict[str, int] = {}
        self.fail = fail

    def pipeline(self, transaction: bool = True) -> FakePipeline:
        return FakePipeline(self.store, self.fail)

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_allows_until_limit_then_blocks() -> None:
    limiter = RedisRateLimiter(FakeRedis())  # type: ignore[arg-type]
    results = [await limiter.allow("register:ip:1", 2, 60) for _ in range(3)]
    assert results == [True, True, False]


@pytest.mark.asyncio
async def test_keys_are_independent() -> None:
    limiter = RedisRateLimiter(FakeRedis())  # type: ignore[arg-type]
    assert await limiter.allow("a", 1, 60)
    assert await limiter.allow("b", 1, 60)
    assert not await limiter.allow("a", 1, 60)


@pytest.mark.asyncio
async def test_login_fails_closed_when_redis_down() -> None:
    limiter = RedisRateLimiter(FakeRedis(fail=True))  # type: ignore[arg-type]
    assert not await limiter.allow("login:ip:1", 5, 60)


@pytest.mark.asyncio
async def test_other_keys_fail_open_when_redis_down() -> None:
    limiter = RedisRateLimiter(FakeRedis(fail=True))  # type: ignore[arg-type]
    assert await limiter.allow("domain-verify:u:1", 5, 60)
