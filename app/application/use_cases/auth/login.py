from dataclasses import dataclass

from app.application.ports.password_hasher import PasswordHasher
from app.application.ports.repositories import UserRepository
from app.application.ports.token_service import TokenService
from app.application.use_cases.auth.session import AuthRateLimiter, SessionIssuer, SessionTokens
from app.domain.errors import InvalidCredentialsError


@dataclass(frozen=True)
class MfaChallenge:
    mfa_token: str


LoginResult = SessionTokens | MfaChallenge


class Login:
    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
        tokens: TokenService,
        issuer: SessionIssuer,
        limiter: AuthRateLimiter,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._tokens = tokens
        self._issuer = issuer
        self._limiter = limiter

    async def execute(self, email: str, password: str, client_ip: str) -> LoginResult:
        normalized = email.strip().lower()
        await self._limiter.check(f"login:ip:{client_ip}", f"login:email:{normalized}")
        user = await self._users.get_by_email(normalized)
        if user is None:
            await self._hasher.verify_dummy(password)
            raise InvalidCredentialsError
        if not await self._hasher.verify(user.password_hash, password):
            raise InvalidCredentialsError
        if user.mfa_enabled:
            return MfaChallenge(self._tokens.issue_mfa_token(user.id))
        return await self._issuer.open_session(user)
