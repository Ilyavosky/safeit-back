import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt

from app.application.ports.clock import Clock
from app.application.ports.token_service import AccessClaims, IssuedAccessToken
from app.domain.errors import InvalidTokenError
from app.domain.value_objects.role import Role

ISSUER = "safeit"
ACCESS_TYPE = "access"
MFA_TYPE = "mfa"
MFA_TOKEN_TTL = timedelta(minutes=5)


class JwtTokenService:
    def __init__(
        self,
        secret: str,
        algorithm: str,
        access_ttl: timedelta,
        clock: Clock,
    ) -> None:
        self._secret = secret
        self._algorithm = algorithm
        self._access_ttl = access_ttl
        self._clock = clock

    def issue_access_token(self, user_id: UUID, role: Role) -> IssuedAccessToken:
        token = self._encode(ACCESS_TYPE, user_id, self._access_ttl, {"role": role.value})
        return IssuedAccessToken(token=token, expires_in=int(self._access_ttl.total_seconds()))

    def decode_access_token(self, token: str) -> AccessClaims:
        payload = self._decode(token, ACCESS_TYPE)
        try:
            role = Role(str(payload["role"]))
        except (KeyError, ValueError) as exc:
            raise InvalidTokenError from exc
        return AccessClaims(
            user_id=self._subject(payload),
            role=role,
            expires_at=self._expires_at(payload),
        )

    def issue_mfa_token(self, user_id: UUID) -> str:
        return self._encode(MFA_TYPE, user_id, MFA_TOKEN_TTL, {})

    def decode_mfa_token(self, token: str) -> UUID:
        return self._subject(self._decode(token, MFA_TYPE))

    def new_refresh_token(self) -> str:
        return secrets.token_urlsafe(48)

    def hash_refresh_token(self, raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def _encode(
        self,
        token_type: str,
        user_id: UUID,
        ttl: timedelta,
        extra: dict[str, str],
    ) -> str:
        issued_at = self._clock.now()
        payload: dict[str, object] = {
            "iss": ISSUER,
            "sub": str(user_id),
            "typ": token_type,
            "jti": uuid.uuid4().hex,
            "iat": int(issued_at.timestamp()),
            "exp": int((issued_at + ttl).timestamp()),
            **extra,
        }
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    def _decode(self, token: str, expected_type: str) -> dict[str, object]:
        try:
            payload: dict[str, object] = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=ISSUER,
                options={
                    "verify_exp": False,
                    "require": ["exp", "iat", "sub", "typ", "iss"],
                },
            )
        except jwt.PyJWTError as exc:
            raise InvalidTokenError from exc
        if payload.get("typ") != expected_type:
            raise InvalidTokenError
        if self._expires_at(payload) <= self._clock.now():
            raise InvalidTokenError
        return payload

    @staticmethod
    def _expires_at(payload: dict[str, object]) -> datetime:
        exp = payload.get("exp")
        if not isinstance(exp, int | float):
            raise InvalidTokenError
        return datetime.fromtimestamp(exp, tz=UTC)

    @staticmethod
    def _subject(payload: dict[str, object]) -> UUID:
        try:
            return UUID(str(payload["sub"]))
        except (KeyError, ValueError) as exc:
            raise InvalidTokenError from exc
