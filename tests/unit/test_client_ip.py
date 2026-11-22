from types import SimpleNamespace
from typing import Any

from app.interfaces.api.dependencies import get_client_ip


def _request(hops: int, header: str | None, peer: str | None = "10.0.0.5") -> Any:
    headers = {} if header is None else {"x-forwarded-for": header}
    return SimpleNamespace(
        client=None if peer is None else SimpleNamespace(host=peer),
        headers=headers,
        app=SimpleNamespace(
            state=SimpleNamespace(
                container=SimpleNamespace(settings=SimpleNamespace(trusted_proxy_hops=hops))
            )
        ),
    )


def test_without_trusted_proxy_the_header_is_ignored() -> None:
    assert get_client_ip(_request(0, "1.2.3.4")) == "10.0.0.5"


def test_one_hop_uses_the_entry_added_by_the_proxy() -> None:
    assert get_client_ip(_request(1, "9.9.9.9, 203.0.113.7")) == "203.0.113.7"


def test_spoofed_leading_entries_are_not_trusted() -> None:
    assert get_client_ip(_request(1, "6.6.6.6, 6.6.6.7, 198.51.100.2")) == "198.51.100.2"


def test_two_hops_skip_the_inner_proxy() -> None:
    assert get_client_ip(_request(2, "203.0.113.7, 100.64.0.1")) == "203.0.113.7"


def test_missing_header_falls_back_to_peer() -> None:
    assert get_client_ip(_request(1, None)) == "10.0.0.5"


def test_not_enough_entries_falls_back_to_peer() -> None:
    assert get_client_ip(_request(2, "203.0.113.7")) == "10.0.0.5"


def test_invalid_address_falls_back_to_peer() -> None:
    assert get_client_ip(_request(1, "no-es-una-ip")) == "10.0.0.5"


def test_ipv6_is_normalized() -> None:
    assert get_client_ip(_request(1, "2001:DB8:0:0:0:0:0:1")) == "2001:db8::1"


def test_no_peer_and_no_proxy_is_unknown() -> None:
    assert get_client_ip(_request(0, None, peer=None)) == "unknown"
