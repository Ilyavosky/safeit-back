from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool

from app.domain.entities.password_reset_token import PasswordResetToken

_COLUMNS = "id, user_id, token_hash, expires_at, created_at, used_at"


class PostgresPasswordResetTokenRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def add(self, token: PasswordResetToken) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                f"insert into public.password_reset_tokens ({_COLUMNS}) "
                "values (%s, %s, %s, %s, %s, %s)",
                (
                    token.id,
                    token.user_id,
                    token.token_hash,
                    token.expires_at,
                    token.created_at,
                    token.used_at,
                ),
            )

    async def get_by_hash(self, token_hash: str) -> PasswordResetToken | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                f"select {_COLUMNS} from public.password_reset_tokens where token_hash = %s",
                (token_hash,),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        return PasswordResetToken(
            id=row[0],
            user_id=row[1],
            token_hash=row[2],
            expires_at=row[3],
            created_at=row[4],
            used_at=row[5],
        )

    async def consume(self, token_id: UUID, now: datetime) -> bool:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "update public.password_reset_tokens set used_at = %s "
                "where id = %s and used_at is null and expires_at > %s",
                (now, token_id, now),
            )
            consumed: bool = cursor.rowcount == 1
        return consumed

    async def invalidate_for_user(self, user_id: UUID, now: datetime) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "update public.password_reset_tokens set used_at = %s "
                "where user_id = %s and used_at is null",
                (now, user_id),
            )
