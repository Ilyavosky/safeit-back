from dataclasses import dataclass, replace
from uuid import UUID

from app.application.ports.repositories import UserRepository
from app.application.ports.secret_cipher import SecretCipher
from app.application.ports.token_service import TokenService
from app.application.ports.totp import TotpService
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.auth.session import AuthRateLimiter, SessionIssuer, SessionTokens
from app.domain.entities.user import User
from app.domain.errors import ConflictError, InvalidMfaCodeError, InvalidTokenError


@dataclass(frozen=True)
class MfaSetup:
    secret: str
    provisioning_uri: str


class SetupMfa:
    def __init__(
        self,
        users: UserRepository,
        totp: TotpService,
        cipher: SecretCipher,
    ) -> None:
        self._users = users
        self._totp = totp
        self._cipher = cipher

    async def execute(self, user_id: UUID) -> MfaSetup:
        user = await _require_user(self._users, user_id)
        if user.mfa_enabled:
            raise ConflictError("La verificación en dos pasos ya está activada.")
        secret = self._totp.generate_secret()
        encrypted = self._cipher.encrypt(secret, str(user.id))
        await self._users.save(replace(user, totp_secret_enc=encrypted))
        return MfaSetup(
            secret=secret, provisioning_uri=self._totp.provisioning_uri(secret, user.email)
        )


class EnableMfa:
    def __init__(
        self,
        users: UserRepository,
        totp: TotpService,
        cipher: SecretCipher,
        limiter: AuthRateLimiter,
    ) -> None:
        self._users = users
        self._totp = totp
        self._cipher = cipher
        self._limiter = limiter

    async def execute(self, user_id: UUID, code: str) -> None:
        await self._limiter.check(f"mfa-enable:user:{user_id}")
        user = await _require_user(self._users, user_id)
        if user.mfa_enabled:
            raise ConflictError("La verificación en dos pasos ya está activada.")
        if user.totp_secret_enc is None:
            raise ConflictError("Primero inicia la configuración de la verificación en dos pasos.")
        secret = self._cipher.decrypt(user.totp_secret_enc, str(user.id))
        if not self._totp.verify(secret, code):
            raise InvalidMfaCodeError
        await self._users.save(replace(user, mfa_enabled=True))


class VerifyMfa:
    def __init__(
        self,
        users: UserRepository,
        tokens: TokenService,
        totp: TotpService,
        cipher: SecretCipher,
        issuer: SessionIssuer,
        limiter: AuthRateLimiter,
        audit: RecordAction,
    ) -> None:
        self._users = users
        self._tokens = tokens
        self._totp = totp
        self._cipher = cipher
        self._issuer = issuer
        self._limiter = limiter
        self._audit = audit

    async def execute(self, mfa_token: str, code: str, client_ip: str) -> SessionTokens:
        await self._limiter.check(f"mfa:ip:{client_ip}")
        user_id = self._tokens.decode_mfa_token(mfa_token)
        await self._limiter.check(f"mfa:user:{user_id}")
        user = await self._users.get_by_id(user_id)
        if user is None or not user.mfa_enabled or user.totp_secret_enc is None:
            raise InvalidTokenError
        secret = self._cipher.decrypt(user.totp_secret_enc, str(user.id))
        if not self._totp.verify(secret, code):
            await self._audit.execute("auth.mfa_failed", user_id=user.id, detail={"ip": client_ip})
            raise InvalidMfaCodeError
        session = await self._issuer.open_session(user)
        await self._audit.execute(
            "auth.login", user_id=user.id, detail={"ip": client_ip, "mfa": True}
        )
        return session


async def _require_user(users: UserRepository, user_id: UUID) -> User:
    user = await users.get_by_id(user_id)
    if user is None:
        raise InvalidTokenError
    return user
