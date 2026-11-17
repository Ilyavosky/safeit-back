from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.domain.entities.refresh_token import RefreshToken
from app.domain.entities.user import User
from app.domain.errors import ConflictError
from app.domain.value_objects.role import Role


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
