import base64
import binascii
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["dev", "prod"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    cors_origins: list[str] = ["http://localhost:3000"]

    database_url: SecretStr
    db_pool_min_size: int = Field(default=1, ge=1)
    db_pool_max_size: int = Field(default=10, ge=1)
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: SecretStr = Field(min_length=32)
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_ttl_minutes: int = Field(default=15, ge=1)
    refresh_token_ttl_days: int = Field(default=7, ge=1)

    auth_rate_limit_attempts: int = Field(default=5, ge=1)
    auth_rate_limit_window_seconds: int = Field(default=60, ge=1)
    domain_verify_rate_limit_attempts: int = Field(default=10, ge=1)

    encryption_key: SecretStr

    nvd_api_key: SecretStr | None = None
    cve_sync_max_lookups: int = Field(default=200, ge=0)

    recon_timeout_seconds: int = Field(default=900, ge=30)
    recon_max_assets: int = Field(default=200, ge=1)
    subfinder_bin: str = "subfinder"
    nmap_bin: str = "nmap"
    httpx_bin: str = "httpx"

    nuclei_bin: str = "nuclei"
    testssl_bin: str = "testssl.sh"

    llm_api_key: SecretStr | None = None
    llm_model: str | None = None
    llm_provider: Literal["anthropic", "openai"] = "anthropic"
    llm_base_url: str = "https://api.anthropic.com"
    llm_max_tokens_per_scan: int = Field(default=200000, ge=1000)
    llm_request_timeout_seconds: int = Field(default=60, ge=5)
    llm_step_timeout_seconds: int = Field(default=300, ge=10)

    @field_validator("encryption_key")
    @classmethod
    def validate_encryption_key(cls, value: SecretStr) -> SecretStr:
        try:
            raw = base64.b64decode(value.get_secret_value(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("encryption_key must be valid base64") from exc
        if len(raw) != 32:
            raise ValueError("encryption_key must decode to 32 bytes for AES-256-GCM")
        return value

    @property
    def recon_stale_after_seconds(self) -> int:
        return self.recon_timeout_seconds * 2

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"


@lru_cache
def get_settings() -> Settings:
    return Settings()
