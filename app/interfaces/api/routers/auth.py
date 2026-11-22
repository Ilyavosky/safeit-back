from typing import Annotated

import structlog
from fastapi import APIRouter, BackgroundTasks, Cookie, Depends, Request, Response, status

from app.application.ports.mailer import EmailMessage, Mailer
from app.application.use_cases.auth.login import MfaChallenge
from app.application.use_cases.auth.session import SessionTokens
from app.container import Container
from app.domain.errors import DomainError, InvalidTokenError
from app.interfaces.api.dependencies import ClientIp, CurrentUser, get_container
from app.interfaces.api.schemas.auth import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    MfaChallengeResponse,
    MfaEnableRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse,
)

REFRESH_COOKIE = "safeit_refresh"
FORGOT_MESSAGE = "Si el correo existe, te enviamos un enlace para restablecer la contraseña."

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

ContainerDep = Annotated[Container, Depends(get_container)]


def _user_response(user: object) -> UserResponse:
    return UserResponse.model_validate(user, from_attributes=True)


def _set_refresh_cookie(response: Response, container: Container, session: SessionTokens) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=session.refresh_token,
        expires=session.refresh_expires_at,
        httponly=True,
        secure=container.settings.is_prod,
        samesite="strict",
        path=container.settings.refresh_cookie_path,
    )


def _token_response(session: SessionTokens) -> TokenResponse:
    return TokenResponse(access_token=session.access_token, expires_in=session.expires_in)


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
async def register(body: RegisterRequest, container: ContainerDep, ip: ClientIp) -> UserResponse:
    user = await container.register_user.execute(body.email, body.password, ip)
    return _user_response(user)


@router.post("/login", response_model=TokenResponse | MfaChallengeResponse)
async def login(
    body: LoginRequest,
    response: Response,
    container: ContainerDep,
    ip: ClientIp,
) -> TokenResponse | MfaChallengeResponse:
    result = await container.login.execute(body.email, body.password, ip)
    if isinstance(result, MfaChallenge):
        return MfaChallengeResponse(mfa_token=result.mfa_token)
    _set_refresh_cookie(response, container, result)
    return _token_response(result)


async def _deliver(mailer: Mailer, message: EmailMessage) -> None:
    try:
        await mailer.send(message)
    except DomainError as exc:
        log.warning("password_reset_mail_failed", code=exc.code)


@router.post(
    "/password/forgot",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ForgotPasswordResponse,
)
async def forgot_password(
    body: ForgotPasswordRequest,
    background: BackgroundTasks,
    container: ContainerDep,
    ip: ClientIp,
) -> ForgotPasswordResponse:
    message = await container.request_password_reset.execute(body.email, ip)
    if message is not None:
        background.add_task(_deliver, container.mailer, message)
    return ForgotPasswordResponse(message=FORGOT_MESSAGE)


@router.post("/password/reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    body: ResetPasswordRequest,
    response: Response,
    container: ContainerDep,
    ip: ClientIp,
) -> None:
    await container.confirm_password_reset.execute(body.token, body.new_password, ip)
    response.delete_cookie(REFRESH_COOKIE, path=container.settings.refresh_cookie_path)


@router.post("/mfa/verify", response_model=TokenResponse)
async def verify_mfa(
    body: MfaVerifyRequest,
    response: Response,
    container: ContainerDep,
    ip: ClientIp,
) -> TokenResponse:
    session = await container.verify_mfa.execute(body.mfa_token, body.code, ip)
    _set_refresh_cookie(response, container, session)
    return _token_response(session)


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def setup_mfa(user: CurrentUser, container: ContainerDep) -> MfaSetupResponse:
    setup = await container.setup_mfa.execute(user.id)
    return MfaSetupResponse(secret=setup.secret, otpauth_uri=setup.provisioning_uri)


@router.post("/mfa/enable", status_code=status.HTTP_204_NO_CONTENT)
async def enable_mfa(body: MfaEnableRequest, user: CurrentUser, container: ContainerDep) -> None:
    await container.enable_mfa.execute(user.id, body.code)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    container: ContainerDep,
    ip: ClientIp,
    refresh_token: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> TokenResponse:
    if not refresh_token:
        raise InvalidTokenError
    session = await container.rotate_refresh_token.execute(refresh_token, ip)
    _set_refresh_cookie(response, container, session)
    return _token_response(session)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    container: ContainerDep,
    refresh_token: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> None:
    await container.logout.execute(refresh_token)
    response.delete_cookie(REFRESH_COOKIE, path=container.settings.refresh_cookie_path)
