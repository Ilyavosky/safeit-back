import argparse
import asyncio
import sys
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from app.config import get_settings
from app.container import build_container
from app.domain.errors import DomainError, OutOfScopeError
from app.domain.services.scope_policy import ensure_url_in_scope
from app.infrastructure.db.session import PostgresDatabase


async def seed(domain_id: UUID, url: str) -> str:
    container = build_container(get_settings())
    await container.database.open()
    try:
        database = container.database
        if not isinstance(database, PostgresDatabase):
            raise TypeError("Se necesita PostgresDatabase.")
        pool: Any = database.pool
        async with pool.connection() as conn, conn.transaction():
            cursor = await conn.execute(
                "select name, user_id, status from public.domains where id = %s", (domain_id,)
            )
            row = await cursor.fetchone()
            if row is None or row[2] != "verified":
                raise OutOfScopeError("El dominio no existe o no está verificado.")
            host = ensure_url_in_scope(url, row[0])
            scan_id, asset_id = uuid4(), uuid4()
            await conn.execute(
                "insert into public.scans (id, domain_id, started_by, type, status, started_at, "
                "finished_at) values (%s, %s, %s, 'recon', 'done', now(), now())",
                (scan_id, domain_id, row[1]),
            )
            cursor = await conn.execute(
                "insert into public.assets (id, domain_id, scan_id, kind, value, in_scope) "
                "values (%s, %s, %s, 'subdomain', %s, true) "
                "on conflict (domain_id, kind, value) do update set in_scope = true "
                "returning id",
                (asset_id, domain_id, scan_id, host),
            )
            asset = await cursor.fetchone()
            await conn.execute(
                "insert into public.endpoints (asset_id, url, http_status, technologies, "
                "whitelisted) values (%s, %s, null, %s, true) "
                "on conflict (asset_id, url) do update set whitelisted = true",
                (asset[0], url, Jsonb([])),
            )
        return f"{urlsplit(url).scheme}://{host}"
    finally:
        await container.database.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Registra un endpoint en alcance y en lista blanca de un dominio verificado."
    )
    parser.add_argument("--domain-id", required=True, type=UUID)
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    try:
        target = asyncio.run(seed(args.domain_id, args.url))
    except DomainError as exc:
        print(exc.message, file=sys.stderr)
        return 1
    print(f"Endpoint listo para pruebas: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
