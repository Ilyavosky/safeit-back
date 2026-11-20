from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.refresh_token import RefreshToken

_COLUMNS = "id, user_id, family_id, token_hash, expires_at, revoked_at, replaced_by"
_INSERT = f"insert into public.refresh_tokens ({_COLUMNS}) values (%s, %s, %s, %s, %s, %s, %s)"


def _params(token: RefreshToken) -> tuple[Any, ...]:
    return (
        token.id,
        token.user_id,
        token.family_id,
        token.token_hash,
        token.expires_at,
        token.revoked_at,
        token.replaced_by,
    )


class PostgresRefreshTokenRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def add(self, token: RefreshToken) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(_INSERT, _params(token))

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                f"select {_COLUMNS} from public.refresh_tokens where token_hash = %s",
                (token_hash,),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        return RefreshToken(
            id=row[0],
            user_id=row[1],
            family_id=row[2],
            token_hash=row[3],
            expires_at=row[4],
            revoked_at=row[5],
            replaced_by=row[6],
        )

    async def rotate(self, old_id: UUID, new: RefreshToken, now: datetime) -> bool:
        rotated = False
        async with self._pool.connection() as conn, conn.transaction():
            await conn.execute(_INSERT, _params(new))
            cursor = await conn.execute(
                "update public.refresh_tokens set revoked_at = %s, replaced_by = %s "
                "where id = %s and revoked_at is null",
                (now, new.id, old_id),
            )
            if cursor.rowcount != 1:
                raise psycopg.Rollback
            rotated = True
        return rotated

    async def revoke_family(self, family_id: UUID, now: datetime) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "update public.refresh_tokens set revoked_at = %s "
                "where family_id = %s and revoked_at is null",
                (now, family_id),
            )

    async def revoke_all_for_user(self, user_id: UUID, now: datetime) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "update public.refresh_tokens set revoked_at = %s "
                "where user_id = %s and revoked_at is null",
                (now, user_id),
            )
