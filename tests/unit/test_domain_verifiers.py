import asyncio
import ssl
from dataclasses import dataclass, field

import dns.exception
import dns.resolver

from app.domain.services.domain_verification import TOKEN_PREFIX, file_path
from app.domain.value_objects.verification_method import VerificationMethod
from app.infrastructure.verification.composite import CompositeDomainVerifier
from app.infrastructure.verification.dns_txt import DnsTxtVerifier
from app.infrastructure.verification.well_known_file import WellKnownFileVerifier

TOKEN = TOKEN_PREFIX + "0123456789abcdef"
PUBLIC_IP = "93.184.216.34"


class _Rdata:
    def __init__(self, *strings: bytes) -> None:
        self.strings = strings


class _Resolver:
    def __init__(self, answer: list[_Rdata] | Exception) -> None:
        self.answer = answer
        self.queried: list[tuple[str, str]] = []

    async def resolve(self, qname: str, rdtype: str, lifetime: float) -> list[_Rdata]:
        self.queried.append((qname, rdtype))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _dns(answer: list[_Rdata] | Exception) -> tuple[DnsTxtVerifier, _Resolver]:
    resolver = _Resolver(answer)
    return DnsTxtVerifier(resolver=resolver), resolver  # type: ignore[arg-type]


async def test_dns_accepts_matching_txt_record() -> None:
    verifier, resolver = _dns([_Rdata(b"other"), _Rdata(TOKEN.encode())])
    assert await verifier.check("example.com", TOKEN) is True
    assert resolver.queried == [("_safeit-verify.example.com", "TXT")]


async def test_dns_joins_split_txt_strings() -> None:
    verifier, _ = _dns([_Rdata(TOKEN[:10].encode(), TOKEN[10:].encode())])
    assert await verifier.check("example.com", TOKEN) is True


async def test_dns_rejects_wrong_value() -> None:
    verifier, _ = _dns([_Rdata(b"safeit-verification=other")])
    assert await verifier.check("example.com", TOKEN) is False


async def test_dns_rejects_substring_match() -> None:
    verifier, _ = _dns([_Rdata(f"x {TOKEN} x".encode())])
    assert await verifier.check("example.com", TOKEN) is False


async def test_dns_failures_return_false() -> None:
    for error_type in (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        verifier, _ = _dns(error_type())
        assert await verifier.check("example.com", TOKEN) is False


class _Writer:
    def __init__(self) -> None:
        self.sent = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.sent += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


@dataclass
class _Network:
    addresses: list[str]
    responses: dict[int, bytes] = field(default_factory=dict)
    connections: list[tuple[str, int, bool, str | None]] = field(default_factory=list)
    writers: list[_Writer] = field(default_factory=list)

    async def resolve(self, host: str, port: int) -> list[str]:
        return self.addresses

    async def connect(
        self, ip: str, port: int, context: ssl.SSLContext | None, hostname: str | None
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        self.connections.append((ip, port, context is not None, hostname))
        if port not in self.responses:
            raise ConnectionRefusedError
        reader = asyncio.StreamReader()
        reader.feed_data(self.responses[port])
        reader.feed_eof()
        writer = _Writer()
        self.writers.append(writer)
        return reader, writer  # type: ignore[return-value]


def _file(network: _Network) -> WellKnownFileVerifier:
    return WellKnownFileVerifier(resolve=network.resolve, connect=network.connect, timeout=2.0)


def _ok(body: str) -> bytes:
    return f"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n{body}".encode()


async def test_file_accepts_token_over_https_and_pins_the_resolved_ip() -> None:
    network = _Network([PUBLIC_IP], {443: _ok(TOKEN + "\n")})
    assert await _file(network).check("example.com", TOKEN) is True
    assert network.connections == [(PUBLIC_IP, 443, True, "example.com")]
    request = network.writers[0].sent.decode()
    assert request.startswith(f"GET {file_path(TOKEN)} HTTP/1.0\r\n")
    assert "Host: example.com\r\n" in request
    assert network.writers[0].closed is True


async def test_file_falls_back_to_http() -> None:
    network = _Network([PUBLIC_IP], {80: _ok(TOKEN)})
    assert await _file(network).check("example.com", TOKEN) is True
    assert [c[1] for c in network.connections] == [443, 80]


async def test_file_rejects_redirects_and_errors() -> None:
    redirect = b"HTTP/1.0 302 Found\r\nLocation: http://127.0.0.1/\r\n\r\n" + TOKEN.encode()
    network = _Network(
        [PUBLIC_IP], {443: redirect, 80: b"HTTP/1.0 404 Not Found\r\n\r\n" + TOKEN.encode()}
    )
    assert await _file(network).check("example.com", TOKEN) is False


async def test_file_rejects_wrong_content() -> None:
    network = _Network([PUBLIC_IP], {443: _ok("nope"), 80: _ok("nope")})
    assert await _file(network).check("example.com", TOKEN) is False


async def test_file_blocks_private_resolution_without_connecting() -> None:
    for address in ("127.0.0.1", "10.0.0.8", "169.254.169.254", "::1", "::ffff:10.0.0.1"):
        network = _Network([address], {443: _ok(TOKEN), 80: _ok(TOKEN)})
        assert await _file(network).check("example.com", TOKEN) is False
        assert network.connections == []


async def test_file_blocks_when_any_resolved_address_is_private() -> None:
    network = _Network([PUBLIC_IP, "192.168.0.10"], {443: _ok(TOKEN)})
    assert await _file(network).check("example.com", TOKEN) is False
    assert network.connections == []


async def test_file_ignores_responses_without_headers_end() -> None:
    network = _Network([PUBLIC_IP], {443: TOKEN.encode(), 80: TOKEN.encode()})
    assert await _file(network).check("example.com", TOKEN) is False


async def test_file_times_out_slow_servers() -> None:
    async def slow_resolve(host: str, port: int) -> list[str]:
        await asyncio.sleep(1)
        return [PUBLIC_IP]

    network = _Network([PUBLIC_IP], {443: _ok(TOKEN)})
    verifier = WellKnownFileVerifier(resolve=slow_resolve, connect=network.connect, timeout=0.05)
    assert await verifier.check("example.com", TOKEN) is False


async def test_composite_dispatches_by_method() -> None:
    class _Fixed:
        def __init__(self, result: bool) -> None:
            self.result = result

        async def check(self, name: str, token: str) -> bool:
            return self.result

    composite = CompositeDomainVerifier(_Fixed(True), _Fixed(False))
    assert await composite.is_verified("a.com", VerificationMethod.DNS_TXT, TOKEN) is True
    assert await composite.is_verified("a.com", VerificationMethod.FILE, TOKEN) is False
