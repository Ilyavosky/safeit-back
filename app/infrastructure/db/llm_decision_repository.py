from typing import Any
from uuid import UUID

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.llm_decision import LlmDecision
from app.domain.value_objects.llm_kind import LlmKind


class PostgresLlmDecisionRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def add(self, decision: LlmDecision) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "insert into public.llm_decisions "
                "(id, scan_id, kind, model, input_hash, output_json, validated, justification, "
                "created_at) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    decision.id,
                    decision.scan_id,
                    decision.kind.value,
                    decision.model,
                    decision.input_hash,
                    Jsonb(decision.output),
                    decision.validated,
                    decision.justification,
                    decision.created_at,
                ),
            )

    async def list_by_scan(self, scan_id: UUID) -> list[LlmDecision]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select id, scan_id, kind, model, input_hash, output_json, validated, "
                "justification, created_at from public.llm_decisions "
                "where scan_id = %s order by created_at, id",
                (scan_id,),
            )
            rows = await cursor.fetchall()
        return [
            LlmDecision(
                id=r[0],
                scan_id=r[1],
                kind=LlmKind(r[2]),
                model=r[3],
                input_hash=r[4],
                output=dict(r[5]),
                validated=r[6],
                justification=r[7],
                created_at=r[8],
            )
            for r in rows
        ]
