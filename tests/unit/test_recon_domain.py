import pytest

from app.domain.services.recon_scope import discard_reason, normalize_host


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        (" api.example.com. ", "api.example.com"),
        ("a-b.c1.example.com", "a-b.c1.example.com"),
        ("*.example.com", None),
        ("localhost", None),
        ("-bad.example.com", None),
        ("bad-.example.com", None),
        ("exa mple.com", None),
        ("a..example.com", None),
        ("exam_ple.com", None),
        ("http://example.com", None),
        ("example.com/path", None),
        ("-oX.example.com", None),
        ("", None),
        ("a" * 64 + ".example.com", None),
        (("a" * 60 + ".") * 5 + "com", None),
    ],
)
def test_normalize_host(raw: str, expected: str | None) -> None:
    assert normalize_host(raw) == expected


@pytest.mark.parametrize(
    ("addresses", "reason"),
    [
        ([], "unresolved"),
        (["93.184.216.34"], None),
        (["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"], None),
        (["127.0.0.1"], "address_not_public"),
        (["10.0.0.5"], "address_not_public"),
        (["169.254.169.254"], "address_not_public"),
        (["93.184.216.34", "192.168.1.10"], "address_not_public"),
        (["::1"], "address_not_public"),
        (["no-es-ip"], "address_not_public"),
    ],
)
def test_discard_reason(addresses: list[str], reason: str | None) -> None:
    assert discard_reason(addresses) == reason
