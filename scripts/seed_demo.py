import argparse
import asyncio
import getpass
import sys
from dataclasses import replace
from typing import Any
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from app.config import get_settings
from app.container import Container, build_container
from app.domain.errors import DomainError
from app.domain.value_objects.role import Role
from app.infrastructure.db.session import PostgresDatabase

DEMO_DOMAIN = "demo.example"
DEMO_USERS = (
    ("demo.admin@example.com", Role.ADMIN),
    ("demo.analyst@example.com", Role.ANALYST),
    ("demo.viewer@example.com", Role.VIEWER),
)
DEMO_HOSTS: tuple[tuple[str, str, int, list[str]], ...] = (
    ("www.demo.example", "https://www.demo.example/", 200, ["nginx"]),
    ("api.demo.example", "https://api.demo.example/", 200, ["Express"]),
    ("blog.demo.example", "https://blog.demo.example/", 200, ["WordPress"]),
    ("login.demo.example", "https://login.demo.example/", 302, []),
)


async def _ensure_user(container: Container, email: str, role: Role, password: str) -> UUID:
    user = await container.users.get_by_email(email)
    if user is None:
        user = await container.register_user.execute(email, password, "seed-demo")
    if user.role is not role:
        user = replace(user, role=role)
        await container.users.save(user)
    return user.id


async def _ensure_domain(pool: Any, owner: UUID) -> None:
    async with pool.connection() as conn, conn.transaction():
        cursor = await conn.execute(
            "insert into public.domains (id, user_id, name, verification_method, status, "
            "verified_at) values (%s, %s, %s, 'dns_txt', 'verified', now()) "
            "on conflict (user_id, name) do nothing returning id",
            (uuid4(), owner, DEMO_DOMAIN),
        )
        created = await cursor.fetchone()
        if created is None:
            return
        domain_id = created[0]
        scan_id = uuid4()
        await conn.execute(
            "insert into public.scans (id, domain_id, started_by, type, status, started_at, "
            "finished_at) values (%s, %s, %s, 'recon', 'done', now(), now())",
            (scan_id, domain_id, owner),
        )
        for host, url, status, technologies in DEMO_HOSTS:
            cursor = await conn.execute(
                "insert into public.assets (id, domain_id, scan_id, kind, value, in_scope) "
                "values (%s, %s, %s, 'subdomain', %s, true) returning id",
                (uuid4(), domain_id, scan_id, host),
            )
            asset = await cursor.fetchone()
            await conn.execute(
                "insert into public.endpoints (asset_id, url, http_status, technologies, "
                "whitelisted) values (%s, %s, %s, %s, false)",
                (asset[0], url, status, Jsonb(technologies)),
            )


async def seed(password: str, force: bool) -> list[str]:
    settings = get_settings()
    if settings.is_prod and not force:
        raise DomainError("Se niega a correr en producción sin --force.")
    container = build_container(settings)
    await container.database.open()
    try:
        database = container.database
        if not isinstance(database, PostgresDatabase):
            raise TypeError("Se necesita PostgresDatabase.")
        owner = await _ensure_user(container, DEMO_USERS[1][0], DEMO_USERS[1][1], password)
        for email, role in (DEMO_USERS[0], DEMO_USERS[2]):
            await _ensure_user(container, email, role, password)
        await _ensure_domain(database.pool, owner)
        return [email for email, _ in DEMO_USERS]
    finally:
        await container.database.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crea usuarios de demostración (uno por rol) y un dominio demo ya verificado."
    )
    parser.add_argument("--force", action="store_true", help="Permite correr con ENVIRONMENT=prod.")
    args = parser.parse_args()
    password = getpass.getpass("Contraseña para los usuarios de demo: ")
    try:
        emails = asyncio.run(seed(password, args.force))
    except DomainError as exc:
        print(exc.message, file=sys.stderr)
        return 1
    print("Usuarios de demo listos: " + ", ".join(emails))
    print(f"Dominio demo verificado: {DEMO_DOMAIN}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
