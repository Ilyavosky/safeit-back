from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool

from app.domain.entities.scan import Scan
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.scan_type import ScanType

_COLUMNS = "id, domain_id, started_by, type, status, created_at, started_at, finished_at"


def _to_scan(row: tuple[Any, ...]) -> Scan:
    return Scan(
        id=row[0],
        domain_id=row[1],
        started_by=row[2],
        type=ScanType(row[3]),
        status=JobStatus(row[4]),
        created_at=row[5],
        started_at=row[6],
        finished_at=row[7],
    )


class PostgresScanRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def add(self, scan: Scan) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                f"insert into public.scans ({_COLUMNS}) values (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    scan.id,
                    scan.domain_id,
                    scan.started_by,
                    scan.type.value,
                    scan.status.value,
                    scan.created_at,
                    scan.started_at,
                    scan.finished_at,
                ),
            )

    async def get(self, scan_id: UUID) -> Scan | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                f"select {_COLUMNS} from public.scans where id = %s", (scan_id,)
            )
            row = await cursor.fetchone()
        return _to_scan(row) if row else None

    async def save(self, scan: Scan) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "update public.scans set status = %s, started_at = %s, finished_at = %s "
                "where id = %s",
                (scan.status.value, scan.started_at, scan.finished_at, scan.id),
            )
