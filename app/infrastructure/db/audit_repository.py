import json
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.audit_entry import AuditEntry

_COLUMNS = "id, user_id, action, entity, entity_id, detail, prev_hash, hash, created_at"


def _dumps(value: Any) -> str:
    return json.dumps(value, default=str, ensure_ascii=False)


def _to_entry(row: tuple[Any, ...]) -> AuditEntry:
    return AuditEntry(
        id=row[0],
        user_id=row[1],
        action=row[2],
        entity=row[3],
        entity_id=row[4],
        detail=row[5],
        prev_hash=row[6],
        hash=row[7],
        created_at=row[8],
    )


class PostgresAuditRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def record(
        self,
        *,
        user_id: UUID | None,
        action: str,
        entity: str | None,
        entity_id: UUID | None,
        detail: Mapping[str, Any],
    ) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "insert into public.audit_log (user_id, action, entity, entity_id, detail) "
                "values (%s, %s, %s, %s, %s)",
                (user_id, action, entity, entity_id, Jsonb(dict(detail), dumps=_dumps)),
            )

    async def list_entries(
        self,
        *,
        limit: int,
        before_id: int | None,
        user_id: UUID | None,
        action: str | None,
    ) -> list[AuditEntry]:
        conditions: list[str] = []
        params: list[Any] = []
        if before_id is not None:
            conditions.append("id < %s")
            params.append(before_id)
        if user_id is not None:
            conditions.append("user_id = %s")
            params.append(user_id)
        if action is not None:
            conditions.append("action = %s")
            params.append(action)
        where = f"where {' and '.join(conditions)}" if conditions else ""
        params.append(limit)
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                f"select {_COLUMNS} from public.audit_log {where} order by id desc limit %s",
                params,
            )
            rows = await cursor.fetchall()
        return [_to_entry(row) for row in rows]

    async def first_broken_id(self) -> int | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute("select public.verify_audit_chain()")
            row = await cursor.fetchone()
        return None if row is None else row[0]
