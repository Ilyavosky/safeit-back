from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from app.domain.entities.audit_entry import AuditEntry
from app.domain.entities.domain import Domain
from app.domain.entities.refresh_token import RefreshToken
from app.domain.entities.user import User


class UserRepository(Protocol):
    async def get_by_id(self, user_id: UUID) -> User | None: ...

    async def get_by_email(self, email: str) -> User | None: ...

    async def add(self, user: User) -> None: ...

    async def save(self, user: User) -> None: ...


class RefreshTokenRepository(Protocol):
    async def add(self, token: RefreshToken) -> None: ...

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None: ...

    async def rotate(self, old_id: UUID, new: RefreshToken, now: datetime) -> bool: ...

    async def revoke_family(self, family_id: UUID, now: datetime) -> None: ...

    async def revoke_all_for_user(self, user_id: UUID, now: datetime) -> None: ...


class DomainRepository(Protocol):
    async def add(self, domain: Domain) -> None: ...

    async def get_by_id(self, domain_id: UUID) -> Domain | None: ...

    async def get_by_user_and_name(self, user_id: UUID, name: str) -> Domain | None: ...

    async def get_verified_by_name(self, name: str) -> Domain | None: ...

    async def list_by_user(self, user_id: UUID) -> list[Domain]: ...

    async def list_all(self) -> list[Domain]: ...

    async def save(self, domain: Domain) -> None: ...


class AuditRepository(Protocol):
    async def record(
        self,
        *,
        user_id: UUID | None,
        action: str,
        entity: str | None,
        entity_id: UUID | None,
        detail: Mapping[str, Any],
    ) -> None: ...

    async def list_entries(
        self,
        *,
        limit: int,
        before_id: int | None,
        user_id: UUID | None,
        action: str | None,
    ) -> list[AuditEntry]: ...

    async def first_broken_id(self) -> int | None: ...
