from typing import Any
from uuid import UUID

from psycopg.errors import UniqueViolation
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.user import User
from app.domain.errors import ConflictError
from app.domain.value_objects.role import Role

_COLUMNS = "id, email, password_hash, role, totp_secret_enc, mfa_enabled, created_at"
_DUPLICATE_EMAIL = "Ya existe una cuenta con ese correo."


def _to_user(row: tuple[Any, ...]) -> User:
    return User(
        id=row[0],
        email=row[1],
        password_hash=row[2],
        role=Role(row[3]),
        totp_secret_enc=row[4],
        mfa_enabled=row[5],
        created_at=row[6],
    )


class PostgresUserRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def get_by_id(self, user_id: UUID) -> User | None:
        return await self._fetch_one(f"select {_COLUMNS} from public.users where id = %s", user_id)

    async def get_by_email(self, email: str) -> User | None:
        return await self._fetch_one(f"select {_COLUMNS} from public.users where email = %s", email)

    async def add(self, user: User) -> None:
        try:
            async with self._pool.connection() as conn:
                await conn.execute(
                    f"insert into public.users ({_COLUMNS}) values (%s, %s, %s, %s, %s, %s, %s)",
                    (
                        user.id,
                        user.email,
                        user.password_hash,
                        user.role.value,
                        user.totp_secret_enc,
                        user.mfa_enabled,
                        user.created_at,
                    ),
                )
        except UniqueViolation as exc:
            raise ConflictError(_DUPLICATE_EMAIL) from exc

    async def save(self, user: User) -> None:
        try:
            async with self._pool.connection() as conn:
                await conn.execute(
                    "update public.users set email = %s, password_hash = %s, role = %s, "
                    "totp_secret_enc = %s, mfa_enabled = %s where id = %s",
                    (
                        user.email,
                        user.password_hash,
                        user.role.value,
                        user.totp_secret_enc,
                        user.mfa_enabled,
                        user.id,
                    ),
                )
        except UniqueViolation as exc:
            raise ConflictError(_DUPLICATE_EMAIL) from exc

    async def _fetch_one(self, query: str, param: object) -> User | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(query, (param,))
            row = await cursor.fetchone()
        return _to_user(row) if row else None
