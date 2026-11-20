from dataclasses import dataclass

from app.application.ports.password_hasher import PasswordHasher
from app.application.ports.repositories import UserRepository
from app.application.ports.token_service import TokenService
from app.application.use_cases.audit.record_action import RecordAction
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
        audit: RecordAction,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._tokens = tokens
        self._issuer = issuer
        self._limiter = limiter
        self._audit = audit

    async def execute(self, email: str, password: str, client_ip: str) -> LoginResult:
        normalized = email.strip().lower()
        await self._limiter.check(f"login:ip:{client_ip}", f"login:email:{normalized}")
        user = await self._users.get_by_email(normalized)
        if user is None:
            await self._hasher.verify_dummy(password)
            await self._audit.execute("auth.login_failed", detail={"ip": client_ip})
            raise InvalidCredentialsError
        if not await self._hasher.verify(user.password_hash, password):
            await self._audit.execute(
                "auth.login_failed", user_id=user.id, detail={"ip": client_ip}
            )
            raise InvalidCredentialsError
        if user.mfa_enabled:
            return MfaChallenge(self._tokens.issue_mfa_token(user.id))
        session = await self._issuer.open_session(user)
        await self._audit.execute(
            "auth.login", user_id=user.id, detail={"ip": client_ip, "mfa": False}
        )
        return session
