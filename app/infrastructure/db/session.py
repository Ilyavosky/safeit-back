from typing import Any

import structlog
from psycopg_pool import AsyncConnectionPool

log = structlog.get_logger(__name__)


class PostgresDatabase:
    def __init__(self, dsn: str, min_size: int, max_size: int) -> None:
        self._pool: AsyncConnectionPool[Any] = AsyncConnectionPool(
            dsn,
            min_size=min_size,
            max_size=max_size,
            open=False,
            timeout=5,
            kwargs={"autocommit": True},
        )

    @property
    def pool(self) -> AsyncConnectionPool[Any]:
        return self._pool

    async def open(self) -> None:
        await self._pool.open(wait=False)

    async def close(self) -> None:
        await self._pool.close()

    async def ping(self) -> bool:
        try:
            async with self._pool.connection(timeout=2) as conn:
                await conn.execute("select 1")
        except Exception as exc:
            log.warning("db_ping_failed", error=type(exc).__name__)
            return False
        return True
