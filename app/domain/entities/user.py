from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.domain.value_objects.role import Role


@dataclass(frozen=True)
class User:
    id: UUID
    email: str
    password_hash: str
    role: Role
    totp_secret_enc: str | None
    mfa_enabled: bool
    created_at: datetime
