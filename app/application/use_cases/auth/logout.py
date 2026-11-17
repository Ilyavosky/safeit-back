from app.application.ports.clock import Clock
from app.application.ports.repositories import RefreshTokenRepository
from app.application.ports.token_service import TokenService


class Logout:
    def __init__(
        self,
        refresh_tokens: RefreshTokenRepository,
        tokens: TokenService,
        clock: Clock,
    ) -> None:
        self._refresh_tokens = refresh_tokens
        self._tokens = tokens
        self._clock = clock

    async def execute(self, raw_token: str | None) -> None:
        if not raw_token:
            return
        stored = await self._refresh_tokens.get_by_hash(self._tokens.hash_refresh_token(raw_token))
        if stored is not None:
            await self._refresh_tokens.revoke_family(stored.family_id, self._clock.now())
