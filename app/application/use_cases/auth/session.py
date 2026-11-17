from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from app.application.ports.clock import Clock
from app.application.ports.rate_limiter import RateLimiter
from app.application.ports.repositories import RefreshTokenRepository
from app.application.ports.token_service import TokenService
from app.domain.entities.refresh_token import RefreshToken
from app.domain.entities.user import User
from app.domain.errors import RateLimitExceededError


@dataclass(frozen=True)
class SessionTokens:
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_at: datetime


class AuthRateLimiter:
    def __init__(self, limiter: RateLimiter, attempts: int, window_seconds: int) -> None:
        self._limiter = limiter
        self._attempts = attempts
        self._window_seconds = window_seconds

    async def check(self, *keys: str, multiplier: int = 1) -> None:
        limit = self._attempts * multiplier
        for key in keys:
            if not await self._limiter.allow(key, limit, self._window_seconds):
                raise RateLimitExceededError


class SessionIssuer:
    def __init__(
        self,
        tokens: TokenService,
        refresh_tokens: RefreshTokenRepository,
        clock: Clock,
        refresh_ttl: timedelta,
    ) -> None:
        self._tokens = tokens
        self._refresh_tokens = refresh_tokens
        self._clock = clock
        self._refresh_ttl = refresh_ttl

    async def open_session(self, user: User) -> SessionTokens:
        raw, record = self.build_refresh(user.id, uuid4())
        await self._refresh_tokens.add(record)
        return self.tokens_for(user, raw, record)

    def build_refresh(self, user_id: UUID, family_id: UUID) -> tuple[str, RefreshToken]:
        raw = self._tokens.new_refresh_token()
        record = RefreshToken(
            id=uuid4(),
            user_id=user_id,
            family_id=family_id,
            token_hash=self._tokens.hash_refresh_token(raw),
            expires_at=self._clock.now() + self._refresh_ttl,
        )
        return raw, record

    def tokens_for(self, user: User, raw_refresh: str, record: RefreshToken) -> SessionTokens:
        access = self._tokens.issue_access_token(user.id, user.role)
        return SessionTokens(
            access_token=access.token,
            expires_in=access.expires_in,
            refresh_token=raw_refresh,
            refresh_expires_at=record.expires_at,
        )
