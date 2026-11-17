import asyncio
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.refresh_token import RefreshToken
from app.domain.entities.user import User
from app.domain.errors import ConflictError
from app.domain.value_objects.role import Role
from app.infrastructure.db.refresh_token_repository import PostgresRefreshTokenRepository
from app.infrastructure.db.user_repository import PostgresUserRepository

TEST_DSN = os.environ.get("TEST_DATABASE_URL")
AUTH_MIGRATION = (
    Path(__file__).resolve().parents[3] / "bd" / "supabase" / "migrations" / "01_safeit_auth.sql"
)

pytestmark = pytest.mark.skipif(not TEST_DSN, reason="TEST_DATABASE_URL no está definida")


@pytest.fixture
async def pool() -> AsyncIterator[AsyncConnectionPool[Any]]:
    assert TEST_DSN is not None
    if not AUTH_MIGRATION.exists():
        pytest.skip("No se encontró la migración 01_safeit_auth.sql")
    db_pool: AsyncConnectionPool[Any] = AsyncConnectionPool(
        TEST_DSN, min_size=1, max_size=4, open=False, kwargs={"autocommit": True}
    )
    await db_pool.open(wait=True)
    created = False
    try:
        async with db_pool.connection() as conn:
            cursor = await conn.execute("select to_regclass('public.users')")
            row = await cursor.fetchone()
            if row is not None and row[0] is not None:
                pytest.skip("public.users ya existe; usa una base vacía para estas pruebas")
            await conn.execute(AUTH_MIGRATION.read_text(encoding="utf-8"))
            created = True
        yield db_pool
    finally:
        if created:
            async with db_pool.connection() as conn:
                await conn.execute("drop table public.refresh_tokens, public.users cascade")
        await db_pool.close()


def _user(email: str = "ana@example.com") -> User:
    return User(
        id=uuid4(),
        email=email,
        password_hash="hash",
        role=Role.VIEWER,
        totp_secret_enc=None,
        mfa_enabled=False,
        created_at=datetime.now(UTC),
    )


def _token(user_id: UUID, family_id: UUID | None = None, suffix: str = "a") -> RefreshToken:
    return RefreshToken(
        id=uuid4(),
        user_id=user_id,
        family_id=family_id or uuid4(),
        token_hash=f"hash-{suffix}-{uuid4().hex}",
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )


async def _count_tokens(pool: AsyncConnectionPool[Any]) -> int:
    async with pool.connection() as conn:
        cursor = await conn.execute("select count(*) from public.refresh_tokens")
        row = await cursor.fetchone()
    assert row is not None
    return int(row[0])


async def test_user_roundtrip(pool: AsyncConnectionPool[Any]) -> None:
    repo = PostgresUserRepository(pool)
    user = _user()

    await repo.add(user)

    assert await repo.get_by_id(user.id) == user
    assert await repo.get_by_email("ana@example.com") == user
    assert await repo.get_by_email("nadie@example.com") is None


async def test_duplicate_email_raises_conflict(pool: AsyncConnectionPool[Any]) -> None:
    repo = PostgresUserRepository(pool)
    await repo.add(_user())

    with pytest.raises(ConflictError):
        await repo.add(_user())


async def test_save_updates_mutable_columns(pool: AsyncConnectionPool[Any]) -> None:
    repo = PostgresUserRepository(pool)
    user = _user()
    await repo.add(user)
    updated = User(
        id=user.id,
        email="nueva@example.com",
        password_hash="otro-hash",
        role=Role.ANALYST,
        totp_secret_enc="v1:abc",
        mfa_enabled=True,
        created_at=user.created_at,
    )

    await repo.save(updated)

    assert await repo.get_by_id(user.id) == updated


async def test_save_with_taken_email_raises_conflict(pool: AsyncConnectionPool[Any]) -> None:
    repo = PostgresUserRepository(pool)
    first, second = _user("uno@example.com"), _user("dos@example.com")
    await repo.add(first)
    await repo.add(second)

    clash = User(**{**second.__dict__, "email": "uno@example.com"})

    with pytest.raises(ConflictError):
        await repo.save(clash)


async def test_refresh_token_roundtrip(pool: AsyncConnectionPool[Any]) -> None:
    users = PostgresUserRepository(pool)
    tokens = PostgresRefreshTokenRepository(pool)
    user = _user()
    await users.add(user)
    token = _token(user.id)

    await tokens.add(token)

    assert await tokens.get_by_hash(token.token_hash) == token
    assert await tokens.get_by_hash("no-existe") is None


async def test_rotate_marks_old_and_stores_new(pool: AsyncConnectionPool[Any]) -> None:
    users = PostgresUserRepository(pool)
    tokens = PostgresRefreshTokenRepository(pool)
    user = _user()
    await users.add(user)
    old = _token(user.id)
    await tokens.add(old)
    new = _token(user.id, old.family_id, "b")
    now = datetime.now(UTC)

    assert await tokens.rotate(old.id, new, now) is True

    stored_old = await tokens.get_by_hash(old.token_hash)
    assert stored_old is not None
    assert stored_old.revoked_at is not None
    assert stored_old.replaced_by == new.id
    assert await tokens.get_by_hash(new.token_hash) == new


async def test_rotating_a_revoked_token_fails_without_leaving_rows(
    pool: AsyncConnectionPool[Any],
) -> None:
    users = PostgresUserRepository(pool)
    tokens = PostgresRefreshTokenRepository(pool)
    user = _user()
    await users.add(user)
    old = _token(user.id)
    await tokens.add(old)
    now = datetime.now(UTC)
    assert await tokens.rotate(old.id, _token(user.id, old.family_id, "b"), now) is True
    rows_before = await _count_tokens(pool)

    again = _token(user.id, old.family_id, "c")

    assert await tokens.rotate(old.id, again, now) is False
    assert await _count_tokens(pool) == rows_before
    assert await tokens.get_by_hash(again.token_hash) is None


async def test_concurrent_rotation_has_a_single_winner(pool: AsyncConnectionPool[Any]) -> None:
    users = PostgresUserRepository(pool)
    tokens = PostgresRefreshTokenRepository(pool)
    user = _user()
    await users.add(user)
    old = _token(user.id)
    await tokens.add(old)
    now = datetime.now(UTC)

    results = await asyncio.gather(
        *(tokens.rotate(old.id, _token(user.id, old.family_id, str(i)), now) for i in range(4))
    )

    assert sorted(results) == [False, False, False, True]


async def test_revoke_family_and_all_for_user(pool: AsyncConnectionPool[Any]) -> None:
    users = PostgresUserRepository(pool)
    tokens = PostgresRefreshTokenRepository(pool)
    user = _user()
    await users.add(user)
    family_a = _token(user.id)
    family_a_next = _token(user.id, family_a.family_id, "b")
    family_b = _token(user.id)
    for token in (family_a, family_a_next, family_b):
        await tokens.add(token)
    now = datetime.now(UTC)

    await tokens.revoke_family(family_a.family_id, now)

    revoked_a = await tokens.get_by_hash(family_a_next.token_hash)
    untouched_b = await tokens.get_by_hash(family_b.token_hash)
    assert revoked_a is not None
    assert revoked_a.revoked_at is not None
    assert untouched_b is not None
    assert untouched_b.revoked_at is None

    await tokens.revoke_all_for_user(user.id, now)

    final_b = await tokens.get_by_hash(family_b.token_hash)
    assert final_b is not None
    assert final_b.revoked_at is not None
