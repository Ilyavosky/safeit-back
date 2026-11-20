import pytest

from app.domain.errors import WeakPasswordError
from app.domain.services.password_policy import validate_password


def test_accepts_a_long_enough_password() -> None:
    validate_password("correct-horse-battery", "ana@example.com")


@pytest.mark.parametrize(
    "password",
    ["corta", "a" * 129, "aaaaaaaaaaaa", "xxxxanaxxxxxxx"],
)
def test_rejects_weak_passwords(password: str) -> None:
    with pytest.raises(WeakPasswordError):
        validate_password(password, "xxxxana@example.com")


def test_rejects_password_containing_the_email_name() -> None:
    with pytest.raises(WeakPasswordError):
        validate_password("my-fernando-secret-123", "fernando@example.com")
