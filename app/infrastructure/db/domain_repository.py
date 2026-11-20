from typing import Any
from uuid import UUID

from psycopg.errors import UniqueViolation
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.domain import Domain
from app.domain.errors import ConflictError, DomainAlreadyClaimedError
from app.domain.value_objects.domain_status import DomainStatus
from app.domain.value_objects.verification_method import VerificationMethod

_COLUMNS = "id, user_id, name, verification_method, verification_token, status, verified_at"
_VERIFIED_NAME_INDEX = "domains_verified_name_key"


def _to_domain(row: tuple[Any, ...]) -> Domain:
    return Domain(
        id=row[0],
        user_id=row[1],
        name=row[2],
        verification_method=VerificationMethod(row[3]),
        verification_token=row[4],
        status=DomainStatus(row[5]),
        verified_at=row[6],
    )


class PostgresDomainRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def add(self, domain: Domain) -> None:
        try:
            async with self._pool.connection() as conn:
                await conn.execute(
                    f"insert into public.domains ({_COLUMNS}) values (%s, %s, %s, %s, %s, %s, %s)",
                    (
                        domain.id,
                        domain.user_id,
                        domain.name,
                        domain.verification_method.value,
                        domain.verification_token,
                        domain.status.value,
                        domain.verified_at,
                    ),
                )
        except UniqueViolation as exc:
            raise ConflictError("Ya registraste este dominio.") from exc

    async def get_by_id(self, domain_id: UUID) -> Domain | None:
        return await self._one("where id = %s", domain_id)

    async def get_by_user_and_name(self, user_id: UUID, name: str) -> Domain | None:
        return await self._one("where user_id = %s and name = %s", user_id, name)

    async def get_verified_by_name(self, name: str) -> Domain | None:
        return await self._one("where name = %s and status = 'verified'", name)

    async def list_by_user(self, user_id: UUID) -> list[Domain]:
        return await self._many("where user_id = %s", user_id)

    async def list_all(self) -> list[Domain]:
        return await self._many("")

    async def save(self, domain: Domain) -> None:
        try:
            async with self._pool.connection() as conn:
                await conn.execute(
                    "update public.domains set status = %s, verified_at = %s where id = %s",
                    (domain.status.value, domain.verified_at, domain.id),
                )
        except UniqueViolation as exc:
            if exc.diag.constraint_name == _VERIFIED_NAME_INDEX:
                raise DomainAlreadyClaimedError from exc
            raise

    async def _one(self, where: str, *params: Any) -> Domain | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(f"select {_COLUMNS} from public.domains {where}", params)
            row = await cursor.fetchone()
        return None if row is None else _to_domain(row)

    async def _many(self, where: str, *params: Any) -> list[Domain]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                f"select {_COLUMNS} from public.domains {where} order by name", params
            )
            rows = await cursor.fetchall()
        return [_to_domain(row) for row in rows]
