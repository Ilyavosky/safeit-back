from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from app.application.ports.clock import Clock
from app.application.ports.database import DatabasePort
from app.application.ports.password_hasher import PasswordHasher
from app.application.ports.rate_limiter import RateLimiter
from app.application.ports.repositories import RefreshTokenRepository, UserRepository
from app.application.ports.token_service import TokenService
from app.application.use_cases.auth.authenticate import AuthenticateAccessToken
from app.application.use_cases.auth.login import Login
from app.application.use_cases.auth.logout import Logout
from app.application.use_cases.auth.mfa import EnableMfa, SetupMfa, VerifyMfa
from app.application.use_cases.auth.register_user import RegisterUser
from app.application.use_cases.auth.rotate_refresh_token import RotateRefreshToken
from app.application.use_cases.auth.session import AuthRateLimiter, SessionIssuer
from app.application.use_cases.auth.update_profile import UpdateProfile
from app.config import Settings
from app.infrastructure.clock import SystemClock
from app.infrastructure.db.refresh_token_repository import PostgresRefreshTokenRepository
from app.infrastructure.db.session import PostgresDatabase
from app.infrastructure.db.user_repository import PostgresUserRepository
from app.infrastructure.rate_limit import InMemoryRateLimiter
from app.infrastructure.security.aes_gcm_cipher import AesGcmCipher
from app.infrastructure.security.jwt_service import JwtTokenService
from app.infrastructure.security.password_hasher import Argon2PasswordHasher
from app.infrastructure.security.totp import PyOtpTotpService


@dataclass(frozen=True)
class Container:
    settings: Settings
    database: DatabasePort
    users: UserRepository
    tokens: TokenService
    authenticate: AuthenticateAccessToken
    register_user: RegisterUser
    login: Login
    verify_mfa: VerifyMfa
    setup_mfa: SetupMfa
    enable_mfa: EnableMfa
    rotate_refresh_token: RotateRefreshToken
    logout: Logout
    update_profile: UpdateProfile


def build_container(
    settings: Settings,
    *,
    database: DatabasePort | None = None,
    users: UserRepository | None = None,
    refresh_tokens: RefreshTokenRepository | None = None,
    hasher: PasswordHasher | None = None,
    rate_limiter: RateLimiter | None = None,
    clock: Clock | None = None,
) -> Container:
    clock = clock or SystemClock()
    database = database or PostgresDatabase(
        dsn=settings.database_url.get_secret_value(),
        min_size=settings.db_pool_min_size,
        max_size=settings.db_pool_max_size,
    )
    if users is None or refresh_tokens is None:
        pool = _pool_of(database)
        users = users or PostgresUserRepository(pool)
        refresh_tokens = refresh_tokens or PostgresRefreshTokenRepository(pool)

    hasher = hasher or Argon2PasswordHasher()
    cipher = AesGcmCipher(settings.encryption_key.get_secret_value())
    totp = PyOtpTotpService()
    tokens = JwtTokenService(
        secret=settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
        access_ttl=timedelta(minutes=settings.access_token_ttl_minutes),
        clock=clock,
    )
    limiter = AuthRateLimiter(
        rate_limiter or InMemoryRateLimiter(clock),
        attempts=settings.auth_rate_limit_attempts,
        window_seconds=settings.auth_rate_limit_window_seconds,
    )
    issuer = SessionIssuer(
        tokens,
        refresh_tokens,
        clock,
        refresh_ttl=timedelta(days=settings.refresh_token_ttl_days),
    )
    return Container(
        settings=settings,
        database=database,
        users=users,
        tokens=tokens,
        authenticate=AuthenticateAccessToken(users, tokens),
        register_user=RegisterUser(users, hasher, clock, limiter),
        login=Login(users, hasher, tokens, issuer, limiter),
        verify_mfa=VerifyMfa(users, tokens, totp, cipher, issuer, limiter),
        setup_mfa=SetupMfa(users, totp, cipher),
        enable_mfa=EnableMfa(users, totp, cipher, limiter),
        rotate_refresh_token=RotateRefreshToken(
            users, refresh_tokens, tokens, issuer, clock, limiter
        ),
        logout=Logout(refresh_tokens, tokens, clock),
        update_profile=UpdateProfile(users, refresh_tokens, hasher, clock, limiter),
    )


def _pool_of(database: DatabasePort) -> Any:
    if not isinstance(database, PostgresDatabase):
        raise TypeError("Se necesita PostgresDatabase o repositorios explícitos.")
    return database.pool
