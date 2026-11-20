from uuid import uuid4

from app.application.ports.clock import Clock
from app.application.ports.password_hasher import PasswordHasher
from app.application.ports.repositories import UserRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.auth.session import AuthRateLimiter
from app.domain.entities.user import User
from app.domain.errors import ConflictError
from app.domain.services.password_policy import validate_password
from app.domain.value_objects.role import Role


class RegisterUser:
    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher,
        clock: Clock,
        limiter: AuthRateLimiter,
        audit: RecordAction,
    ) -> None:
        self._users = users
        self._hasher = hasher
        self._clock = clock
        self._limiter = limiter
        self._audit = audit

    async def execute(self, email: str, password: str, client_ip: str) -> User:
        await self._limiter.check(f"register:ip:{client_ip}")
        normalized = email.strip().lower()
        validate_password(password, normalized)
        if await self._users.get_by_email(normalized) is not None:
            raise ConflictError("Ya existe una cuenta con ese correo.")
        user = User(
            id=uuid4(),
            email=normalized,
            password_hash=await self._hasher.hash(password),
            role=Role.VIEWER,
            totp_secret_enc=None,
            mfa_enabled=False,
            created_at=self._clock.now(),
        )
        await self._users.add(user)
        await self._audit.execute(
            "auth.register",
            user_id=user.id,
            entity="user",
            entity_id=user.id,
            detail={"ip": client_ip},
        )
        return user
