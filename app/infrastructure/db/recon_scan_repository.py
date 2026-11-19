from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool

from app.domain.entities.scan import Scan


class PostgresReconScanRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def add_if_idle(self, scan: Scan) -> bool:
        async with self._pool.connection() as conn, conn.transaction():
            await conn.execute(
                "select pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"recon:{scan.domain_id}",),
            )
            cursor = await conn.execute(
                "insert into public.scans (id, domain_id, started_by, type, status, created_at) "
                "select %s, %s, %s, 'recon', 'queued', %s "
                "where not exists (select 1 from public.scans where domain_id = %s "
                "and type = 'recon' and status in ('queued', 'running'))",
                (scan.id, scan.domain_id, scan.started_by, scan.created_at, scan.domain_id),
            )
            return bool(cursor.rowcount == 1)

    async def fail_stale(self, domain_id: UUID, cutoff: datetime) -> int:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "update public.scans set status = 'failed', finished_at = now() "
                "where domain_id = %s and type = 'recon' and status in ('queued', 'running') "
                "and created_at < %s",
                (domain_id, cutoff),
            )
            return int(cursor.rowcount)
