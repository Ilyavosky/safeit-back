from app.application.ports.clock import Clock
from app.application.ports.repositories import RefreshTokenRepository, UserRepository
from app.application.ports.token_service import TokenService
from app.application.use_cases.auth.session import AuthRateLimiter, SessionIssuer, SessionTokens
from app.domain.errors import InvalidTokenError, TokenReuseDetectedError

REFRESH_LIMIT_MULTIPLIER = 6


class RotateRefreshToken:
    def __init__(
        self,
        users: UserRepository,
        refresh_tokens: RefreshTokenRepository,
        tokens: TokenService,
        issuer: SessionIssuer,
        clock: Clock,
        limiter: AuthRateLimiter,
    ) -> None:
        self._users = users
        self._refresh_tokens = refresh_tokens
        self._tokens = tokens
        self._issuer = issuer
        self._clock = clock
        self._limiter = limiter

    async def execute(self, raw_token: str, client_ip: str) -> SessionTokens:
        await self._limiter.check(f"refresh:ip:{client_ip}", multiplier=REFRESH_LIMIT_MULTIPLIER)
        now = self._clock.now()
        stored = await self._refresh_tokens.get_by_hash(self._tokens.hash_refresh_token(raw_token))
        if stored is None:
            raise InvalidTokenError
        if stored.replaced_by is not None:
            await self._refresh_tokens.revoke_family(stored.family_id, now)
            raise TokenReuseDetectedError(stored.family_id)
        if stored.revoked_at is not None or stored.expires_at <= now:
            raise InvalidTokenError
        user = await self._users.get_by_id(stored.user_id)
        if user is None:
            raise InvalidTokenError
        raw_new, record = self._issuer.build_refresh(user.id, stored.family_id)
        if not await self._refresh_tokens.rotate(stored.id, record, now):
            await self._refresh_tokens.revoke_family(stored.family_id, now)
            raise TokenReuseDetectedError(stored.family_id)
        return self._issuer.tokens_for(user, raw_new, record)
