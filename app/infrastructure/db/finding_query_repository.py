from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool

from app.application.pagination import decode_cursor, encode_cursor
from app.application.ports.findings_query import (
    FindingFilter,
    FindingPage,
    FindingSort,
    FindingView,
    Scope,
)
from app.domain.entities.finding import Finding
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.severity import Severity

_FROM = (
    "from public.findings f "
    "join public.test_runs r on r.id = f.test_run_id "
    "join public.scans s on s.id = r.scan_id "
    "join public.endpoints e on e.id = f.endpoint_id "
    "join public.assets a on a.id = e.asset_id "
    "join public.domains d on d.id = a.domain_id "
    "left join public.reports rp on rp.scan_id = s.id "
)
_SELECT = (
    "select f.id, f.test_run_id, f.endpoint_id, f.title, f.severity, f.priority_score, "
    "f.remediation_status, f.detected_at, f.is_false_positive, "
    "coalesce((select array_agg(fc.cve_id order by fc.cve_id) "
    "from public.finding_cves fc where fc.finding_id = f.id), '{}'), "
    "d.id, d.name, a.id, a.value, e.url, s.id, s.status, (rp.id is not null) "
)
_LIFECYCLE = (
    "(case when f.is_false_positive then 'false_positive' "
    "when f.remediation_status = 'fixed' then 'resolved' "
    "when f.remediation_status = 'in_progress' then 'in_remediation' "
    "when s.status in ('queued', 'running') then 'discovered' "
    "when s.status = 'done' and rp.id is null then 'in_analysis' "
    "else 'confirmed' end)"
)
_LATEST_SCAN = (
    "s.id = (select s2.id from public.scans s2 where s2.domain_id = s.domain_id "
    "and s2.type = 'tests' and s2.status = 'done' order by s2.created_at desc, s2.id desc limit 1)"
)
_SORT_KEYS = {
    FindingSort.PRIORITY: "coalesce(f.priority_score, -1)::float8::text",
    FindingSort.DETECTED: "f.detected_at::text",
}


def _row_to_view(row: Any) -> FindingView:
    finding = Finding(
        id=row[0],
        test_run_id=row[1],
        endpoint_id=row[2],
        title=row[3],
        severity=Severity(row[4]),
        priority_score=float(row[5]) if row[5] is not None else None,
        remediation_status=RemediationStatus(row[6]),
        detected_at=row[7],
        is_false_positive=row[8],
        cve_ids=tuple(row[9]),
    )
    return FindingView(
        finding=finding,
        domain_id=row[10],
        domain_name=row[11],
        asset_id=row[12],
        asset_value=row[13],
        url=row[14],
        scan_id=row[15],
        scan_status=JobStatus(row[16]),
        has_report=row[17],
    )


def _scope_where(scope: Scope, *, active_only: bool = True) -> tuple[str, list[Any]]:
    clauses = ["not f.is_false_positive"] if active_only else []
    params: list[Any] = []
    if scope.owner_id is not None:
        clauses.append("d.user_id = %s")
        params.append(scope.owner_id)
    if scope.domain_id is not None:
        clauses.append("d.id = %s")
        params.append(scope.domain_id)
    if scope.scan_id is not None:
        clauses.append("s.id = %s")
        params.append(scope.scan_id)
    else:
        clauses.append(_LATEST_SCAN)
    return " and ".join(clauses) or "true", params


class PostgresFindingQueryRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def get(self, finding_id: UUID) -> FindingView | None:
        found = await self.get_many([finding_id])
        return found.get(finding_id)

    async def get_many(self, finding_ids: list[UUID]) -> dict[UUID, FindingView]:
        if not finding_ids:
            return {}
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                f"{_SELECT}{_FROM}where f.id = any(%s)",
                (finding_ids,),
            )
            rows = await cursor.fetchall()
        views = [_row_to_view(r) for r in rows]
        return {v.finding.id: v for v in views}

    async def list_page(
        self,
        owner_id: UUID | None,
        filters: FindingFilter,
        sort: FindingSort,
        cursor: str | None,
        limit: int,
    ) -> FindingPage:
        key = _SORT_KEYS[sort]
        clauses: list[str] = []
        params: list[Any] = []
        if filters.lifecycle is None:
            clauses.append("not f.is_false_positive")
        else:
            clauses.append(f"{_LIFECYCLE} = %s")
            params.append(filters.lifecycle.value)
        if owner_id is not None:
            clauses.append("d.user_id = %s")
            params.append(owner_id)
        if filters.severity is not None:
            clauses.append("f.severity = %s")
            params.append(filters.severity.value)
        if filters.asset_id is not None:
            clauses.append("a.id = %s")
            params.append(filters.asset_id)
        if filters.domain_id is not None:
            clauses.append("d.id = %s")
            params.append(filters.domain_id)
        if filters.scan_id is not None:
            clauses.append("s.id = %s")
            params.append(filters.scan_id)
        if cursor is not None:
            last_key, last_id = decode_cursor(cursor)
            cast = "::float8" if sort is FindingSort.PRIORITY else "::timestamptz"
            expr = (
                "coalesce(f.priority_score, -1)::float8"
                if sort is FindingSort.PRIORITY
                else "f.detected_at"
            )
            clauses.append(f"({expr}, f.id) < (%s{cast}, %s)")
            params.extend([last_key, last_id])
        where = " and ".join(clauses) or "true"
        async with self._pool.connection() as conn:
            result = await conn.execute(
                f"{_SELECT}, {key} {_FROM}where {where} "
                f"order by {key.replace('::text', '')} desc, f.id desc limit %s",
                (*params, limit + 1),
            )
            rows = await result.fetchall()
        has_more = len(rows) > limit
        page = rows[:limit]
        next_cursor = encode_cursor(page[-1][18], page[-1][0]) if has_more and page else None
        return FindingPage([_row_to_view(r) for r in page], next_cursor)

    async def set_remediation(self, finding_id: UUID, status: RemediationStatus) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "update public.findings set remediation_status = %s where id = %s",
                (status.value, finding_id),
            )

    async def severity_counts(self, scope: Scope) -> dict[Severity, int]:
        where, params = _scope_where(scope)
        rows = await self._fetch(
            f"select f.severity, count(*) {_FROM}where {where} group by f.severity", params
        )
        return {Severity(r[0]): int(r[1]) for r in rows}

    async def remediation_counts(self, scope: Scope) -> dict[RemediationStatus, int]:
        where, params = _scope_where(scope)
        rows = await self._fetch(
            f"select f.remediation_status, count(*) {_FROM}where {where} "
            "group by f.remediation_status",
            params,
        )
        return {RemediationStatus(r[0]): int(r[1]) for r in rows}

    async def latest(self, scope: Scope, limit: int) -> list[FindingView]:
        where, params = _scope_where(scope)
        rows = await self._fetch(
            f"{_SELECT}{_FROM}where {where} order by f.detected_at desc, f.id desc limit %s",
            [*params, limit],
        )
        return [_row_to_view(r) for r in rows]

    async def asset_count(self, scope: Scope) -> int:
        clauses = ["a.in_scope"]
        params: list[Any] = []
        if scope.owner_id is not None:
            clauses.append("d.user_id = %s")
            params.append(scope.owner_id)
        if scope.domain_id is not None:
            clauses.append("d.id = %s")
            params.append(scope.domain_id)
        rows = await self._fetch(
            "select count(*) from public.assets a join public.domains d on d.id = a.domain_id "
            f"where {' and '.join(clauses)}",
            params,
        )
        return int(rows[0][0])

    async def scan_status_counts(self, scope: Scope) -> dict[JobStatus, int]:
        clauses = ["true"]
        params: list[Any] = []
        if scope.owner_id is not None:
            clauses.append("d.user_id = %s")
            params.append(scope.owner_id)
        if scope.domain_id is not None:
            clauses.append("d.id = %s")
            params.append(scope.domain_id)
        if scope.scan_id is not None:
            clauses.append("s.id = %s")
            params.append(scope.scan_id)
        rows = await self._fetch(
            "select s.status, count(*) from public.scans s "
            "join public.domains d on d.id = s.domain_id "
            f"where {' and '.join(clauses)} group by s.status",
            params,
        )
        return {JobStatus(r[0]): int(r[1]) for r in rows}

    async def latest_report_scan_id(self, owner_id: UUID | None) -> UUID | None:
        clauses = ["true"]
        params: list[Any] = []
        if owner_id is not None:
            clauses.append("d.user_id = %s")
            params.append(owner_id)
        rows = await self._fetch(
            "select r.scan_id from public.reports r "
            "join public.scans s on s.id = r.scan_id "
            "join public.domains d on d.id = s.domain_id "
            f"where {' and '.join(clauses)} order by r.created_at desc, r.id desc limit 1",
            params,
        )
        return rows[0][0] if rows else None

    async def _fetch(self, sql: str, params: list[Any]) -> list[Any]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(sql, params)
            return list(await cursor.fetchall())
