import base64

import pytest
from pydantic import ValidationError

from app.config import Settings


def _build(**overrides: str) -> Settings:
    values = {
        "database_url": "postgresql://u:p@localhost:5432/db",
        "jwt_secret": "s" * 32,
        "encryption_key": base64.b64encode(bytes(32)).decode(),
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_valid_settings_load() -> None:
    settings = _build()

    assert settings.environment == "dev"
    assert settings.is_prod is False


def test_encryption_key_must_be_base64() -> None:
    with pytest.raises(ValidationError):
        _build(encryption_key="no es base64 !!")


def test_encryption_key_must_be_32_bytes() -> None:
    with pytest.raises(ValidationError):
        _build(encryption_key=base64.b64encode(bytes(16)).decode())


def test_jwt_secret_needs_32_characters() -> None:
    with pytest.raises(ValidationError):
        _build(jwt_secret="corto")
