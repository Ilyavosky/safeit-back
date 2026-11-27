from collections.abc import Sequence
from typing import Any
from uuid import UUID

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.asset import Asset
from app.domain.entities.discovered import DiscoveredService, HttpProbe
from app.domain.entities.endpoint import Endpoint
from app.domain.value_objects.asset_kind import AssetKind
from app.infrastructure.db.sql_builder import query

_ASSET = "id, domain_id, scan_id, kind, value, in_scope, discovered_at"
_ENDPOINT = (
    "e.id, e.asset_id, a.domain_id, e.url, e.http_status, e.technologies, e.whitelisted, a.in_scope"
)


def _to_asset(row: tuple[Any, ...]) -> Asset:
    return Asset(row[0], row[1], row[2], AssetKind(row[3]), row[4], row[5], row[6])


def _to_endpoint(row: tuple[Any, ...]) -> Endpoint:
    return Endpoint(
        id=row[0],
        asset_id=row[1],
        domain_id=row[2],
        url=row[3],
        http_status=row[4],
        technologies=tuple(str(t) for t in (row[5] or [])),
        whitelisted=row[6],
        in_scope=row[7],
    )


class PostgresAssetRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def upsert(self, asset: Asset) -> Asset:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query(
                    "insert into public.assets ({asset}) values (%s, %s, %s, %s, %s, %s, %s) "
                    "on conflict (domain_id, kind, value) do update set scan_id = "
                    "excluded.scan_id, in_scope = excluded.in_scope returning {asset}",
                    asset=_ASSET,
                ),
                (
                    asset.id,
                    asset.domain_id,
                    asset.scan_id,
                    asset.kind.value,
                    asset.value,
                    asset.in_scope,
                    asset.discovered_at,
                ),
            )
            row = await cursor.fetchone()
        if row is None:
            raise RuntimeError("upsert de asset sin fila")
        return _to_asset(row)

    async def replace_services(self, asset_id: UUID, services: Sequence[DiscoveredService]) -> None:
        async with self._pool.connection() as conn, conn.transaction():
            await conn.execute("delete from public.services where asset_id = %s", (asset_id,))
            for service in services:
                await conn.execute(
                    "insert into public.services (asset_id, port, protocol, name, version, banner) "
                    "values (%s, %s, %s, %s, %s, %s) on conflict do nothing",
                    (
                        asset_id,
                        service.port,
                        service.protocol,
                        service.name,
                        service.version,
                        service.banner,
                    ),
                )

    async def upsert_endpoint(self, asset_id: UUID, probe: HttpProbe) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "insert into public.endpoints (asset_id, url, http_status, technologies) "
                "values (%s, %s, %s, %s) on conflict (asset_id, url) do update "
                "set http_status = excluded.http_status, technologies = excluded.technologies",
                (asset_id, probe.url, probe.http_status, Jsonb(list(probe.technologies))),
            )

    async def list_by_domain(self, domain_id: UUID) -> list[Asset]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query(
                    "select {asset} from public.assets where domain_id = %s order by kind, value",
                    asset=_ASSET,
                ),
                (domain_id,),
            )
            return [_to_asset(row) for row in await cursor.fetchall()]

    async def get(self, asset_id: UUID) -> Asset | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query("select {asset} from public.assets where id = %s", asset=_ASSET), (asset_id,)
            )
            row = await cursor.fetchone()
        return _to_asset(row) if row else None

    async def list_services(self, asset_id: UUID) -> list[DiscoveredService]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select port, protocol, name, version, banner from public.services "
                "where asset_id = %s order by port, protocol",
                (asset_id,),
            )
            return [DiscoveredService(*row) for row in await cursor.fetchall()]

    async def list_endpoints(self, asset_id: UUID) -> list[Endpoint]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query(
                    "select {endpoint} from public.endpoints e join public.assets a on a.id = "
                    "e.asset_id where e.asset_id = %s order by e.url",
                    endpoint=_ENDPOINT,
                ),
                (asset_id,),
            )
            return [_to_endpoint(row) for row in await cursor.fetchall()]

    async def get_endpoint(self, endpoint_id: UUID) -> Endpoint | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query(
                    "select {endpoint} from public.endpoints e join public.assets a on a.id = "
                    "e.asset_id where e.id = %s",
                    endpoint=_ENDPOINT,
                ),
                (endpoint_id,),
            )
            row = await cursor.fetchone()
        return _to_endpoint(row) if row else None

    async def set_whitelisted(self, endpoint_id: UUID, whitelisted: bool) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "update public.endpoints set whitelisted = %s where id = %s",
                (whitelisted, endpoint_id),
            )
