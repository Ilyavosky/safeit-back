import pytest

from app.domain.errors import InvalidDomainNameError
from app.domain.services.domain_name import normalize_domain_name
from app.domain.services.domain_verification import (
    TOKEN_PREFIX,
    dns_record_name,
    file_path,
    new_verification_token,
)
from app.domain.services.network_safety import is_public_address


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("  sub.example.com.  ", "sub.example.com"),
        ("a-b.example.co", "a-b.example.co"),
    ],
)
def test_normalize_accepts_valid_names(raw: str, expected: str) -> None:
    assert normalize_domain_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "localhost",
        "192.168.1.1",
        "-bad.example.com",
        "bad-.example.com",
        "exa mple.com",
        "example.com/path",
        "http://example.com",
        "example.com:8080",
        "ejemplo.ñandú.com",
        "a" * 64 + ".com",
        ("a." * 130) + "com",
        "example.c",
    ],
)
def test_normalize_rejects_invalid_names(raw: str) -> None:
    with pytest.raises(InvalidDomainNameError):
        normalize_domain_name(raw)


def test_verification_token_is_random_and_prefixed() -> None:
    first, second = new_verification_token(), new_verification_token()
    assert first != second
    assert first.startswith(TOKEN_PREFIX)
    assert len(first) <= 128


def test_verification_locations() -> None:
    token = TOKEN_PREFIX + "abc123"
    assert dns_record_name("example.com") == "_safeit-verify.example.com"
    assert file_path(token) == "/.well-known/safeit-abc123.txt"


@pytest.mark.parametrize("address", ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(address: str) -> None:
    assert is_public_address(address) is True


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.10",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",  # noqa: S104
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "2002:7f00:0001::1",
        "64:ff9b::a00:1",
        "fe80::1%eth0",
        "not-an-ip",
        "",
    ],
)
def test_non_public_addresses_are_blocked(address: str) -> None:
    assert is_public_address(address) is False
