import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.domain import Domain
from app.domain.entities.scan import Scan
from app.domain.entities.user import User
from app.domain.value_objects.domain_status import DomainStatus
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.role import Role
from app.domain.value_objects.scan_type import ScanType
from app.domain.value_objects.verification_method import VerificationMethod
from app.infrastructure.db.domain_repository import PostgresDomainRepository
from app.infrastructure.db.scan_repository import PostgresScanRepository
from app.infrastructure.db.user_repository import PostgresUserRepository

NUCLEI_POLICY = {
    "tags_allowlist": ["cve", "misconfig", "exposure", "tech"],
    "tags_denylist": ["dos", "intrusive", "fuzz", "bruteforce"],
    "rate_limit": 50,
    "timeout_s": 600,
}


@dataclass(frozen=True)
class World:
    user: User
    domain: Domain
    recon_scan: Scan
    asset_id: UUID
    endpoint_id: UUID
    tool_ids: dict[str, UUID]


async def seed_world(
    pool: AsyncConnectionPool[Any],
    *,
    verified: bool = True,
    in_scope: bool = True,
    whitelisted: bool = True,
    url: str = "https://example.com/",
    domain_name: str = "example.com",
) -> World:
    now = datetime.now(UTC)
    user = User(uuid4(), f"{uuid4()}@x.com", "hash", Role.ANALYST, None, False, now)
    await PostgresUserRepository(pool).add(user)
    domain = Domain(
        uuid4(),
        user.id,
        domain_name,
        VerificationMethod.DNS_TXT,
        "tok",
        DomainStatus.VERIFIED if verified else DomainStatus.PENDING,
        now if verified else None,
    )
    domains = PostgresDomainRepository(pool)
    await domains.add(domain)
    if verified:
        await domains.save(domain)
    recon = Scan(uuid4(), domain.id, user.id, ScanType.RECON, JobStatus.DONE, now)
    asset_id, endpoint_id = uuid4(), uuid4()
    tool_ids = {"headers": uuid4(), "testssl": uuid4(), "nuclei": uuid4()}
    async with pool.connection() as conn:
        if not verified:
            await conn.execute(
                "update public.domains set status = 'verified', verified_at = now() where id = %s",
                (domain.id,),
            )
        await PostgresScanRepository(pool).add(recon)
        if not verified:
            await conn.execute(
                "update public.domains set status = 'pending', verified_at = null where id = %s",
                (domain.id,),
            )
        await conn.execute(
            "insert into public.assets (id, domain_id, scan_id, kind, value, in_scope) "
            "values (%s, %s, %s, 'subdomain', %s, %s)",
            (asset_id, domain.id, recon.id, domain_name, in_scope),
        )
        await conn.execute(
            "insert into public.endpoints (id, asset_id, url, http_status, technologies, "
            "whitelisted) values (%s, %s, %s, 200, %s, %s)",
            (endpoint_id, asset_id, url, Jsonb(["nginx"]), whitelisted),
        )
        for name, tool_id in tool_ids.items():
            params = NUCLEI_POLICY if name == "nuclei" else {"timeout_s": 60}
            await conn.execute(
                "insert into public.allowed_tools (id, name, allowed_params, active) "
                "values (%s, %s, %s::jsonb, true) on conflict (name) do nothing",
                (tool_id, name, json.dumps(params)),
            )
        cursor = await conn.execute("select name, id from public.allowed_tools")
        tool_ids = {row[0]: row[1] for row in await cursor.fetchall()}
    return World(user, domain, recon, asset_id, endpoint_id, tool_ids)
