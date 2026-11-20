from typing import Any

from psycopg_pool import AsyncConnectionPool

from app.domain.entities.allowed_tool import AllowedTool


class PostgresToolRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def list_active(self) -> list[AllowedTool]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select id, name, allowed_params, active from public.allowed_tools "
                "where active order by name"
            )
            rows = await cursor.fetchall()
        return [
            AllowedTool(id=r[0], name=r[1], allowed_params=dict(r[2]), active=r[3]) for r in rows
        ]

    async def get_by_name(self, name: str) -> AllowedTool | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select id, name, allowed_params, active from public.allowed_tools where name = %s",
                (name,),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        return AllowedTool(id=row[0], name=row[1], allowed_params=dict(row[2]), active=row[3])
