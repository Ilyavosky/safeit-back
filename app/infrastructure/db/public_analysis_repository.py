from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.public_analysis import PublicAnalysis, PublicHost
from app.domain.value_objects.host_kind import HostKind
from app.domain.value_objects.job_status import JobStatus
from app.infrastructure.db.sql_builder import query

_COLUMNS = (
    "id, user_id, domain, status, summary, summary_model, stats, error, "
    "created_at, finished_at, expires_at"
)
_HOST_COLUMNS = (
    "id, host, kind, http_status, title, technologies, provider, redirect_host, "
    "security_headers, tls_issuer, tls_valid, tls_valid_until"
)


def _analysis(row: Sequence[Any]) -> PublicAnalysis:
    return PublicAnalysis(
        id=row[0],
        user_id=row[1],
        domain=row[2],
        status=JobStatus(row[3]),
        summary=row[4],
        summary_model=row[5],
        stats=row[6] or {},
        error=row[7],
        created_at=row[8],
        finished_at=row[9],
        expires_at=row[10],
    )


def _host(row: Sequence[Any]) -> PublicHost:
    return PublicHost(
        id=row[0],
        host=row[1],
        kind=HostKind(row[2]),
        http_status=row[3],
        title=row[4],
        technologies=tuple(row[5] or ()),
        provider=row[6],
        redirect_host=row[7],
        security_headers=tuple(row[8] or ()),
        tls_issuer=row[9],
        tls_valid=row[10],
        tls_valid_until=row[11],
    )


class PostgresPublicAnalysisRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def add_if_idle(self, analysis: PublicAnalysis) -> bool:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query(
                    "insert into public.public_analyses ({columns}) values (%s, %s, %s, %s, "
                    "%s, %s, %s, %s, %s, %s, %s) on conflict (user_id) where status in "
                    "('queued', 'running') do nothing returning id",
                    columns=_COLUMNS,
                ),
                (
                    analysis.id,
                    analysis.user_id,
                    analysis.domain,
                    analysis.status.value,
                    analysis.summary,
                    analysis.summary_model,
                    Jsonb(analysis.stats),
                    analysis.error,
                    analysis.created_at,
                    analysis.finished_at,
                    analysis.expires_at,
                ),
            )
            return await cursor.fetchone() is not None

    async def save(self, analysis: PublicAnalysis) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "update public.public_analyses set status = %s, summary = %s, "
                "summary_model = %s, stats = %s, error = %s, finished_at = %s where id = %s",
                (
                    analysis.status.value,
                    analysis.summary,
                    analysis.summary_model,
                    Jsonb(analysis.stats),
                    analysis.error,
                    analysis.finished_at,
                    analysis.id,
                ),
            )

    async def get(self, analysis_id: UUID) -> PublicAnalysis | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query(
                    "select {columns} from public.public_analyses where id = %s", columns=_COLUMNS
                ),
                (analysis_id,),
            )
            row = await cursor.fetchone()
        return _analysis(row) if row else None

    async def list_by_user(self, user_id: UUID, limit: int) -> list[PublicAnalysis]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query(
                    "select {columns} from public.public_analyses where user_id = %s and "
                    "expires_at > now() order by created_at desc limit %s",
                    columns=_COLUMNS,
                ),
                (user_id, limit),
            )
            rows = await cursor.fetchall()
        return [_analysis(row) for row in rows]

    async def count_since(self, user_id: UUID, since: datetime) -> int:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select count(*) from public.public_analyses "
                "where user_id = %s and created_at >= %s",
                (user_id, since),
            )
            row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def fail_stale(self, user_id: UUID, cutoff: datetime) -> int:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "update public.public_analyses set status = 'failed', finished_at = now(), "
                "error = 'El análisis superó el tiempo máximo.' "
                "where user_id = %s and status in ('queued', 'running') and created_at < %s",
                (user_id, cutoff),
            )
            return int(cursor.rowcount)

    async def replace_hosts(self, analysis_id: UUID, hosts: Sequence[PublicHost]) -> None:
        async with self._pool.connection() as conn, conn.transaction():
            await conn.execute(
                "delete from public.public_analysis_hosts where analysis_id = %s", (analysis_id,)
            )
            for host in hosts:
                await conn.execute(
                    "insert into public.public_analysis_hosts "
                    "(analysis_id, host, kind, http_status, title, "
                    "technologies, provider, redirect_host, security_headers, tls_issuer, "
                    "tls_valid, tls_valid_until) "
                    "values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        analysis_id,
                        host.host,
                        host.kind.value,
                        host.http_status,
                        host.title,
                        list(host.technologies),
                        host.provider,
                        host.redirect_host,
                        list(host.security_headers),
                        host.tls_issuer,
                        host.tls_valid,
                        host.tls_valid_until,
                    ),
                )

    async def list_hosts(self, analysis_id: UUID) -> list[PublicHost]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query(
                    "select {host_columns} from public.public_analysis_hosts where analysis_id "
                    "= %s order by host",
                    host_columns=_HOST_COLUMNS,
                ),
                (analysis_id,),
            )
            rows = await cursor.fetchall()
        return [_host(row) for row in rows]

    async def delete_expired(self, now: datetime) -> int:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "delete from public.public_analyses where expires_at <= %s", (now,)
            )
            return int(cursor.rowcount)
