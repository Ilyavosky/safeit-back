import hashlib
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.domain.entities.audit_entry import AuditEntry
from app.domain.entities.domain import Domain
from app.domain.entities.refresh_token import RefreshToken
from app.domain.entities.user import User
from app.domain.errors import ConflictError, DomainAlreadyClaimedError
from app.domain.value_objects.role import Role
from app.domain.value_objects.verification_method import VerificationMethod


class FakeDatabase:
    def __init__(self, up: bool = True) -> None:
        self.up = up
        self.opened = False
        self.closed = False

    async def open(self) -> None:
        self.opened = True

    async def close(self) -> None:
        self.closed = True

    async def ping(self) -> bool:
        return self.up


class FakeClock:
    def __init__(self) -> None:
        self._now = datetime.now(UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, **kwargs: float) -> None:
        self._now += timedelta(**kwargs)


class InMemoryUserRepository:
    def __init__(self) -> None:
        self.users: dict[UUID, User] = {}

    async def get_by_id(self, user_id: UUID) -> User | None:
        return self.users.get(user_id)

    async def get_by_email(self, email: str) -> User | None:
        return next((u for u in self.users.values() if u.email == email), None)

    async def add(self, user: User) -> None:
        self._ensure_unique_email(user)
        self.users[user.id] = user

    async def save(self, user: User) -> None:
        self._ensure_unique_email(user)
        self.users[user.id] = user

    def by_email(self, email: str) -> User:
        return next(u for u in self.users.values() if u.email == email)

    def set_role(self, email: str, role: Role) -> None:
        user = self.by_email(email)
        self.users[user.id] = replace(user, role=role)

    def delete(self, email: str) -> None:
        del self.users[self.by_email(email).id]

    def _ensure_unique_email(self, user: User) -> None:
        for other in self.users.values():
            if other.email == user.email and other.id != user.id:
                raise ConflictError("Ya existe una cuenta con ese correo.")


class InMemoryRefreshTokenRepository:
    def __init__(self) -> None:
        self.tokens: dict[UUID, RefreshToken] = {}

    async def add(self, token: RefreshToken) -> None:
        self.tokens[token.id] = token

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        return next((t for t in self.tokens.values() if t.token_hash == token_hash), None)

    async def rotate(self, old_id: UUID, new: RefreshToken, now: datetime) -> bool:
        old = self.tokens[old_id]
        if old.revoked_at is not None:
            return False
        self.tokens[new.id] = new
        self.tokens[old_id] = replace(old, revoked_at=now, replaced_by=new.id)
        return True

    async def revoke_family(self, family_id: UUID, now: datetime) -> None:
        for token_id, token in list(self.tokens.items()):
            if token.family_id == family_id and token.revoked_at is None:
                self.tokens[token_id] = replace(token, revoked_at=now)

    async def revoke_all_for_user(self, user_id: UUID, now: datetime) -> None:
        for token_id, token in list(self.tokens.items()):
            if token.user_id == user_id and token.revoked_at is None:
                self.tokens[token_id] = replace(token, revoked_at=now)

    def active_count(self) -> int:
        return sum(1 for t in self.tokens.values() if t.revoked_at is None)


class InMemoryAuditRepository:
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []
        self.broken_at: int | None = None

    async def record(
        self,
        *,
        user_id: UUID | None,
        action: str,
        entity: str | None,
        entity_id: UUID | None,
        detail: Mapping[str, Any],
    ) -> None:
        prev_hash = self.entries[-1].hash if self.entries else None
        entry_id = len(self.entries) + 1
        digest = hashlib.sha256(f"{entry_id}|{prev_hash}|{action}".encode()).hexdigest()
        self.entries.append(
            AuditEntry(
                id=entry_id,
                user_id=user_id,
                action=action,
                entity=entity,
                entity_id=entity_id,
                detail=dict(detail),
                prev_hash=prev_hash,
                hash=digest,
                created_at=datetime.now(UTC),
            )
        )

    async def list_entries(
        self,
        *,
        limit: int,
        before_id: int | None,
        user_id: UUID | None,
        action: str | None,
    ) -> list[AuditEntry]:
        matching = [
            e
            for e in reversed(self.entries)
            if (before_id is None or e.id < before_id)
            and (user_id is None or e.user_id == user_id)
            and (action is None or e.action == action)
        ]
        return matching[:limit]

    async def first_broken_id(self) -> int | None:
        return self.broken_at

    def actions(self) -> list[str]:
        return [e.action for e in self.entries]


class InMemoryDomainRepository:
    def __init__(self) -> None:
        self.domains: dict[UUID, Domain] = {}

    async def add(self, domain: Domain) -> None:
        if await self.get_by_user_and_name(domain.user_id, domain.name) is not None:
            raise ConflictError("Ya registraste este dominio.")
        self.domains[domain.id] = domain

    async def get_by_id(self, domain_id: UUID) -> Domain | None:
        return self.domains.get(domain_id)

    async def get_by_user_and_name(self, user_id: UUID, name: str) -> Domain | None:
        return next(
            (d for d in self.domains.values() if d.user_id == user_id and d.name == name), None
        )

    async def get_verified_by_name(self, name: str) -> Domain | None:
        return next((d for d in self.domains.values() if d.name == name and d.is_verified), None)

    async def list_by_user(self, user_id: UUID) -> list[Domain]:
        return sorted((d for d in self.domains.values() if d.user_id == user_id), key=_by_name)

    async def list_all(self) -> list[Domain]:
        return sorted(self.domains.values(), key=_by_name)

    async def save(self, domain: Domain) -> None:
        if domain.is_verified:
            other = await self.get_verified_by_name(domain.name)
            if other is not None and other.id != domain.id:
                raise DomainAlreadyClaimedError
        self.domains[domain.id] = domain


def _by_name(domain: Domain) -> str:
    return domain.name


class FakeDomainVerifier:
    def __init__(self) -> None:
        self.verified_names: set[str] = set()
        self.calls: list[tuple[str, VerificationMethod, str]] = []

    async def is_verified(self, name: str, method: VerificationMethod, token: str) -> bool:
        self.calls.append((name, method, token))
        return name in self.verified_names
