from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool

from app.domain.entities.endpoint import Endpoint


class PostgresEndpointRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def list_testable(self, domain_id: UUID) -> list[Endpoint]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select e.id, e.asset_id, a.domain_id, e.url, e.http_status, e.technologies, "
                "e.whitelisted, a.in_scope "
                "from public.endpoints e join public.assets a on a.id = e.asset_id "
                "where a.domain_id = %s and e.whitelisted and a.in_scope "
                "order by e.url, e.id",
                (domain_id,),
            )
            rows = await cursor.fetchall()
        return [
            Endpoint(
                id=row[0],
                asset_id=row[1],
                domain_id=row[2],
                url=row[3],
                http_status=row[4],
                technologies=tuple(str(t) for t in (row[5] or [])),
                whitelisted=row[6],
                in_scope=row[7],
            )
            for row in rows
        ]
