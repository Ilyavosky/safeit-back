from typing import Any
from uuid import uuid4

import psycopg
import pytest
from psycopg_pool import AsyncConnectionPool

from tests.pg_seed import World, seed_world


async def _insert_run(
    pool: AsyncConnectionPool[Any], world: World, scan_id: Any, tool: str = "headers"
) -> None:
    async with pool.connection() as conn:
        await conn.execute(
            "insert into public.test_runs (id, scan_id, endpoint_id, tool_id, params, status) "
            "values (%s, %s, %s, %s, '{}'::jsonb, 'queued')",
            (uuid4(), scan_id, world.endpoint_id, world.tool_ids[tool]),
        )


async def _tests_scan(pool: AsyncConnectionPool[Any], world: World) -> Any:
    scan_id = uuid4()
    async with pool.connection() as conn:
        await conn.execute(
            "insert into public.scans (id, domain_id, started_by, type, status) "
            "values (%s, %s, %s, 'tests', 'queued')",
            (scan_id, world.domain.id, world.user.id),
        )
    return scan_id


async def test_baseline_insert_is_allowed(migrated_pool: AsyncConnectionPool[Any]) -> None:
    world = await seed_world(migrated_pool)
    await _insert_run(migrated_pool, world, await _tests_scan(migrated_pool, world))


async def test_recon_scans_cannot_hold_test_runs(migrated_pool: AsyncConnectionPool[Any]) -> None:
    world = await seed_world(migrated_pool)
    with pytest.raises(psycopg.errors.CheckViolation):
        await _insert_run(migrated_pool, world, world.recon_scan.id)


async def test_out_of_scope_assets_are_never_tested(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    world = await seed_world(migrated_pool, in_scope=False)
    scan_id = await _tests_scan(migrated_pool, world)
    with pytest.raises(psycopg.errors.CheckViolation):
        await _insert_run(migrated_pool, world, scan_id)


async def test_non_whitelisted_endpoints_are_never_tested(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    world = await seed_world(migrated_pool, whitelisted=False)
    scan_id = await _tests_scan(migrated_pool, world)
    with pytest.raises(psycopg.errors.CheckViolation):
        await _insert_run(migrated_pool, world, scan_id)


async def test_inactive_tools_are_never_used(migrated_pool: AsyncConnectionPool[Any]) -> None:
    world = await seed_world(migrated_pool)
    scan_id = await _tests_scan(migrated_pool, world)
    async with migrated_pool.connection() as conn:
        await conn.execute("update public.allowed_tools set active = false where name = 'nuclei'")
    with pytest.raises(psycopg.errors.CheckViolation):
        await _insert_run(migrated_pool, world, scan_id, "nuclei")


async def test_endpoints_of_another_domain_are_rejected(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    world = await seed_world(migrated_pool)
    other = await seed_world(migrated_pool, domain_name="otro.com", url="https://otro.com/")
    scan_id = await _tests_scan(migrated_pool, world)
    async with migrated_pool.connection() as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            await conn.execute(
                "insert into public.test_runs (id, scan_id, endpoint_id, tool_id, params, status) "
                "values (%s, %s, %s, %s, '{}'::jsonb, 'queued')",
                (uuid4(), scan_id, other.endpoint_id, world.tool_ids["headers"]),
            )


async def test_unverified_domains_cannot_be_scanned(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    world = await seed_world(migrated_pool, verified=False)
    async with migrated_pool.connection() as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            await conn.execute(
                "insert into public.scans (id, domain_id, started_by, type, status) "
                "values (%s, %s, %s, 'tests', 'queued')",
                (uuid4(), world.domain.id, world.user.id),
            )
