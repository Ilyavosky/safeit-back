from typing import Any
from uuid import UUID

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.test_run import TestRun
from app.domain.value_objects.job_status import JobStatus


class PostgresTestRunRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def add(self, run: TestRun) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "insert into public.test_runs (id, scan_id, endpoint_id, tool_id, params, status) "
                "values (%s, %s, %s, %s, %s, %s)",
                (
                    run.id,
                    run.scan_id,
                    run.endpoint_id,
                    run.tool_id,
                    Jsonb(run.params),
                    run.status.value,
                ),
            )

    async def save(self, run: TestRun, result_enc: bytes | None) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "update public.test_runs set status = %s, started_at = %s, finished_at = %s, "
                "result_enc = coalesce(%s, result_enc) where id = %s",
                (run.status.value, run.started_at, run.finished_at, result_enc, run.id),
            )

    async def list_by_scan(self, scan_id: UUID) -> list[TestRun]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select r.id, r.scan_id, r.endpoint_id, r.tool_id, t.name, r.params, r.status, "
                "r.started_at, r.finished_at "
                "from public.test_runs r join public.allowed_tools t on t.id = r.tool_id "
                "where r.scan_id = %s order by r.started_at nulls last, r.id",
                (scan_id,),
            )
            rows = await cursor.fetchall()
        return [
            TestRun(
                id=row[0],
                scan_id=row[1],
                endpoint_id=row[2],
                tool_id=row[3],
                tool_name=row[4],
                params=dict(row[5]),
                status=JobStatus(row[6]),
                started_at=row[7],
                finished_at=row[8],
            )
            for row in rows
        ]
