from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.domain.value_objects.role import Role


@dataclass(frozen=True)
class AccessClaims:
    user_id: UUID
    role: Role
    expires_at: datetime


@dataclass(frozen=True)
class IssuedAccessToken:
    token: str
    expires_in: int


class TokenService(Protocol):
    def issue_access_token(self, user_id: UUID, role: Role) -> IssuedAccessToken: ...

    def decode_access_token(self, token: str) -> AccessClaims: ...

    def issue_mfa_token(self, user_id: UUID) -> str: ...

    def decode_mfa_token(self, token: str) -> UUID: ...

    def new_refresh_token(self) -> str: ...

    def hash_refresh_token(self, raw_token: str) -> str: ...
