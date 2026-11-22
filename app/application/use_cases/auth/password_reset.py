from dataclasses import replace
from datetime import timedelta
from html import escape
from urllib.parse import quote
from uuid import uuid4

from app.application.ports.clock import Clock
from app.application.ports.mailer import EmailMessage
from app.application.ports.password_hasher import PasswordHasher
from app.application.ports.repositories import (
    PasswordResetTokenRepository,
    RefreshTokenRepository,
    UserRepository,
)
from app.application.ports.token_service import TokenService
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.auth.session import AuthRateLimiter
from app.domain.entities.password_reset_token import PasswordResetToken
from app.domain.errors import InvalidResetTokenError
from app.domain.services.password_policy import validate_password

RESET_PATH = "/reset-password"


def build_reset_email(to: str, link: str, ttl_minutes: int) -> EmailMessage:
    subject = "Restablece tu contraseña de SafeIT"
    text = (
        "Recibimos una solicitud para restablecer la contraseña de tu cuenta de SafeIT.\n\n"
        f"Abre este enlace para elegir una nueva contraseña (vence en {ttl_minutes} minutos "
        "y solo se puede usar una vez):\n\n"
        f"{link}\n\n"
        "Si no fuiste tú, ignora este correo: tu contraseña actual sigue siendo válida."
    )
    safe_link = escape(link, quote=True)
    html = (
        '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#1b1e23">'
        '<h2 style="margin:0 0 16px">Restablece tu contraseña</h2>'
        "<p>Recibimos una solicitud para restablecer la contraseña de tu cuenta de SafeIT.</p>"
        f'<p><a href="{safe_link}" style="display:inline-block;padding:12px 20px;'
        "background:#8da2fb;color:#10131a;border-radius:10px;text-decoration:none;"
        'font-weight:600">Elegir nueva contraseña</a></p>'
        f"<p>El enlace vence en {ttl_minutes} minutos y solo se puede usar una vez.</p>"
        '<p style="color:#6b7280;font-size:13px">Si no fuiste tú, ignora este correo: '
        "tu contraseña actual sigue siendo válida.</p>"
        "</div>"
    )
    return EmailMessage(to=to, subject=subject, text=text, html=html)


class RequestPasswordReset:
    def __init__(
        self,
        users: UserRepository,
        resets: PasswordResetTokenRepository,
        tokens: TokenService,
        clock: Clock,
        limiter: AuthRateLimiter,
        audit: RecordAction,
        *,
        frontend_url: str,
        ttl: timedelta,
    ) -> None:
        self._users = users
        self._resets = resets
        self._tokens = tokens
        self._clock = clock
        self._limiter = limiter
        self._audit = audit
        self._frontend_url = frontend_url.rstrip("/")
        self._ttl = ttl

    async def execute(self, email: str, client_ip: str) -> EmailMessage | None:
        normalized = email.strip().lower()
        await self._limiter.check(f"pwreset:ip:{client_ip}", f"pwreset:email:{normalized}")
        user = await self._users.get_by_email(normalized)
        if user is None:
            return None
        now = self._clock.now()
        await self._resets.invalidate_for_user(user.id, now)
        raw = self._tokens.new_refresh_token()
        await self._resets.add(
            PasswordResetToken(
                id=uuid4(),
                user_id=user.id,
                token_hash=self._tokens.hash_refresh_token(raw),
                expires_at=now + self._ttl,
                created_at=now,
            )
        )
        await self._audit.execute(
            "auth.password_reset_requested",
            user_id=user.id,
            entity="user",
            entity_id=user.id,
            detail={"ip": client_ip},
        )
        link = f"{self._frontend_url}{RESET_PATH}?token={quote(raw, safe='')}"
        return build_reset_email(user.email, link, int(self._ttl.total_seconds() // 60))


class ConfirmPasswordReset:
    def __init__(
        self,
        users: UserRepository,
        resets: PasswordResetTokenRepository,
        refresh_tokens: RefreshTokenRepository,
        tokens: TokenService,
        hasher: PasswordHasher,
        clock: Clock,
        limiter: AuthRateLimiter,
        audit: RecordAction,
    ) -> None:
        self._users = users
        self._resets = resets
        self._refresh_tokens = refresh_tokens
        self._tokens = tokens
        self._hasher = hasher
        self._clock = clock
        self._limiter = limiter
        self._audit = audit

    async def execute(self, raw_token: str, new_password: str, client_ip: str) -> None:
        await self._limiter.check(f"pwreset-confirm:ip:{client_ip}")
        now = self._clock.now()
        stored = await self._resets.get_by_hash(self._tokens.hash_refresh_token(raw_token))
        if stored is None or stored.used_at is not None or stored.expires_at <= now:
            await self._audit.execute("auth.password_reset_denied", detail={"ip": client_ip})
            raise InvalidResetTokenError
        user = await self._users.get_by_id(stored.user_id)
        if user is None:
            raise InvalidResetTokenError
        validate_password(new_password, user.email)
        if not await self._resets.consume(stored.id, now):
            raise InvalidResetTokenError
        await self._users.save(replace(user, password_hash=await self._hasher.hash(new_password)))
        await self._resets.invalidate_for_user(user.id, now)
        await self._refresh_tokens.revoke_all_for_user(user.id, now)
        await self._audit.execute(
            "auth.password_reset_completed",
            user_id=user.id,
            entity="user",
            entity_id=user.id,
            detail={"ip": client_ip},
        )
