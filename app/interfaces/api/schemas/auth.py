from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, StringConstraints

from app.domain.value_objects.role import Role

Password = Annotated[str, StringConstraints(min_length=1, max_length=256)]
MfaCode = Annotated[str, StringConstraints(pattern=r"^\d{6}$")]


class RegisterRequest(BaseModel):
    email: EmailStr
    password: Password


class LoginRequest(BaseModel):
    email: EmailStr
    password: Password


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    message: str


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: Password


class UserResponse(BaseModel):
    id: UUID
    email: str
    role: Role
    mfa_enabled: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    mfa_required: bool = False


class MfaChallengeResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str


class MfaVerifyRequest(BaseModel):
    mfa_token: str = Field(min_length=1)
    code: MfaCode


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaEnableRequest(BaseModel):
    code: MfaCode


class ProfileUpdateRequest(BaseModel):
    current_password: Password
    email: EmailStr | None = None
    new_password: Password | None = None
