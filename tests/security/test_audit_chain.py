from typing import Any
from uuid import uuid4

import pytest
from psycopg.errors import InsufficientPrivilege
from psycopg_pool import AsyncConnectionPool

from app.infrastructure.db.audit_repository import PostgresAuditRepository


async def _seed(pool: AsyncConnectionPool[Any], count: int = 4) -> PostgresAuditRepository:
    repo = PostgresAuditRepository(pool)
    for index in range(count):
        await repo.record(
            user_id=None,
            action="seed",
            entity="thing",
            entity_id=uuid4(),
            detail={"index": index},
        )
    return repo


@pytest.mark.parametrize(
    "statement",
    [
        "update public.audit_log set action = 'forged'",
        "delete from public.audit_log",
        "truncate public.audit_log",
    ],
)
async def test_audit_log_is_append_only(
    migrated_pool: AsyncConnectionPool[Any], statement: str
) -> None:
    repo = await _seed(migrated_pool)
    async with migrated_pool.connection() as conn:
        with pytest.raises(InsufficientPrivilege):
            await conn.execute(statement)
    assert len(await repo.list_entries(limit=10, before_id=None, user_id=None, action=None)) == 4
    assert await repo.first_broken_id() is None


async def test_tampering_with_a_row_is_detected(migrated_pool: AsyncConnectionPool[Any]) -> None:
    repo = await _seed(migrated_pool)
    entries = await repo.list_entries(limit=10, before_id=None, user_id=None, action=None)
    victim = sorted(entries, key=lambda e: e.id)[1]
    async with migrated_pool.connection() as conn:
        await conn.execute(
            "alter table public.audit_log disable trigger audit_log_no_update_delete_trg"
        )
        await conn.execute(
            "update public.audit_log set detail = '{\"index\": 99}'::jsonb where id = %s",
            (victim.id,),
        )
        await conn.execute(
            "alter table public.audit_log enable trigger audit_log_no_update_delete_trg"
        )
    assert await repo.first_broken_id() == victim.id


async def test_removing_a_row_is_detected(migrated_pool: AsyncConnectionPool[Any]) -> None:
    repo = await _seed(migrated_pool)
    entries = sorted(
        await repo.list_entries(limit=10, before_id=None, user_id=None, action=None),
        key=lambda e: e.id,
    )
    async with migrated_pool.connection() as conn:
        await conn.execute(
            "alter table public.audit_log disable trigger audit_log_no_update_delete_trg"
        )
        await conn.execute("delete from public.audit_log where id = %s", (entries[1].id,))
        await conn.execute(
            "alter table public.audit_log enable trigger audit_log_no_update_delete_trg"
        )
    assert await repo.first_broken_id() == entries[2].id
