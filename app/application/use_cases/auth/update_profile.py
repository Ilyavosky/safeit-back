from dataclasses import replace

from app.application.ports.clock import Clock
from app.application.ports.password_hasher import PasswordHasher
from app.application.ports.repositories import RefreshTokenRepository, UserRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.auth.session import AuthRateLimiter
from app.domain.entities.user import User
from app.domain.errors import ConflictError, InvalidCredentialsError
from app.domain.services.password_policy import validate_password


class UpdateProfile:
    def __init__(
        self,
        users: UserRepository,
        refresh_tokens: RefreshTokenRepository,
        hasher: PasswordHasher,
        clock: Clock,
        limiter: AuthRateLimiter,
        audit: RecordAction,
    ) -> None:
        self._users = users
        self._refresh_tokens = refresh_tokens
        self._hasher = hasher
        self._clock = clock
        self._limiter = limiter
        self._audit = audit

    async def execute(
        self,
        user: User,
        current_password: str,
        email: str | None = None,
        new_password: str | None = None,
    ) -> User:
        await self._limiter.check(f"profile:user:{user.id}")
        if not await self._hasher.verify(user.password_hash, current_password):
            await self._audit.execute("auth.profile_update_denied", user_id=user.id)
            raise InvalidCredentialsError
        updated = user
        target_email = email.strip().lower() if email is not None else user.email
        if target_email != user.email:
            if await self._users.get_by_email(target_email) is not None:
                raise ConflictError("Ya existe una cuenta con ese correo.")
            updated = replace(updated, email=target_email)
        password_changed = new_password is not None
        if new_password is not None:
            validate_password(new_password, target_email)
            updated = replace(updated, password_hash=await self._hasher.hash(new_password))
        if updated == user:
            return user
        await self._users.save(updated)
        if password_changed:
            await self._refresh_tokens.revoke_all_for_user(user.id, self._clock.now())
        await self._audit.execute(
            "auth.profile_updated",
            user_id=user.id,
            entity="user",
            entity_id=user.id,
            detail={
                "email_changed": updated.email != user.email,
                "password_changed": password_changed,
            },
        )
        return updated
