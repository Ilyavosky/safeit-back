import asyncio
import json
import ssl
from types import SimpleNamespace
from typing import Any

import httpx

from app.infrastructure.public.crtsh import CrtShSource
from app.infrastructure.public.dns_inspector import DnsPublicInspector
from app.infrastructure.public.web_fetcher import PublicHttpFetcher


class FakeWriter:
    def __init__(self) -> None:
        self.sent = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.sent += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def get_extra_info(self, name: str) -> Any:
        return None


def _connector(response: bytes, writers: list[FakeWriter], fail_tls: bool = False) -> Any:
    async def connect(
        ip: str, port: int, context: ssl.SSLContext | None, server_hostname: str | None
    ) -> tuple[asyncio.StreamReader, FakeWriter]:
        if fail_tls and context is not None:
            raise ssl.SSLCertVerificationError("bad cert")
        reader = asyncio.StreamReader()
        reader.feed_data(response)
        reader.feed_eof()
        writer = FakeWriter()
        writers.append(writer)
        return reader, writer

    return connect


def _resolver(addresses: list[str]) -> Any:
    async def resolve(host: str, port: int) -> list[str]:
        return addresses

    return resolve


HTML = (
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html; charset=utf-8\r\n"
    b"Strict-Transport-Security: max-age=1\r\n\r\n"
    b"<html><head><title>  Inicio \n de   Ejemplo </title></head></html>"
)


async def test_fetch_extracts_status_title_headers_and_sends_one_get() -> None:
    writers: list[FakeWriter] = []
    fetcher = PublicHttpFetcher(
        resolve=_resolver(["93.184.216.34"]), connect=_connector(HTML, writers)
    )

    result = await fetcher.fetch("ejemplo.com")

    assert result is not None
    assert result.http_status == 200
    assert result.title == "Inicio de Ejemplo"
    assert result.content_type == "text/html"
    assert result.headers["Server"] == "nginx/1.18.0"
    assert len(writers) == 1
    assert writers[0].sent.startswith(b"GET / HTTP/1.1\r\nHost: ejemplo.com\r\n")


async def test_fetch_never_connects_to_private_addresses() -> None:
    writers: list[FakeWriter] = []
    fetcher = PublicHttpFetcher(resolve=_resolver(["10.0.0.5"]), connect=_connector(HTML, writers))

    assert await fetcher.fetch("interno.ejemplo.com") is None
    assert writers == []


async def test_fetch_rejects_mixed_public_and_private_resolution() -> None:
    writers: list[FakeWriter] = []
    fetcher = PublicHttpFetcher(
        resolve=_resolver(["93.184.216.34", "127.0.0.1"]), connect=_connector(HTML, writers)
    )

    assert await fetcher.fetch("rebind.ejemplo.com") is None
    assert writers == []


async def test_fetch_reports_redirect_host() -> None:
    redirect = b"HTTP/1.1 301 Moved\r\nLocation: https://www.ejemplo.com/inicio\r\n\r\n"
    fetcher = PublicHttpFetcher(
        resolve=_resolver(["93.184.216.34"]), connect=_connector(redirect, [])
    )

    result = await fetcher.fetch("ejemplo.com")

    assert result is not None
    assert result.redirect_host == "www.ejemplo.com"


async def test_fetch_falls_back_to_http_when_tls_fails_completely() -> None:
    async def connect(
        ip: str, port: int, context: ssl.SSLContext | None, server_hostname: str | None
    ) -> tuple[asyncio.StreamReader, FakeWriter]:
        if context is not None:
            raise ConnectionRefusedError
        reader = asyncio.StreamReader()
        reader.feed_data(HTML)
        reader.feed_eof()
        return reader, FakeWriter()

    fetcher = PublicHttpFetcher(
        resolve=_resolver(["93.184.216.34"]),
        connect=connect,  # type: ignore[arg-type]
    )

    result = await fetcher.fetch("ejemplo.com")

    assert result is not None
    assert result.tls is None


async def test_garbage_response_yields_nothing() -> None:
    fetcher = PublicHttpFetcher(
        resolve=_resolver(["93.184.216.34"]), connect=_connector(b"hola", [])
    )

    assert await fetcher.fetch("ejemplo.com") is None


async def test_crtsh_filters_wildcards_foreign_names_and_duplicates() -> None:
    rows = [
        {"name_value": "ejemplo.com\n*.ejemplo.com\nwww.ejemplo.com"},
        {"name_value": "api.ejemplo.com\notro-sitio.com"},
        {"name_value": "api.ejemplo.com"},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(rows))

    source = CrtShSource(transport=httpx.MockTransport(handler))

    assert await source.subdomains("ejemplo.com") == [
        "ejemplo.com",
        "www.ejemplo.com",
        "api.ejemplo.com",
    ]


async def test_crtsh_failure_returns_empty() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    assert await CrtShSource(transport=httpx.MockTransport(handler)).subdomains("e.com") == []


class FakeDnsResolver:
    def __init__(self, answers: dict[tuple[str, str], list[Any]]) -> None:
        self._answers = answers

    async def resolve(self, name: str, rtype: str, lifetime: float = 5.0) -> list[Any]:
        import dns.resolver

        if (name, rtype) not in self._answers:
            raise dns.resolver.NoAnswer
        return self._answers[(name, rtype)]


async def test_apex_dns_summary() -> None:
    answers = {
        ("e.com", "NS"): [SimpleNamespace(target="ns1.proveedor.net.")],
        ("e.com", "MX"): [SimpleNamespace(exchange="mx.e.com.")],
        ("e.com", "TXT"): [SimpleNamespace(strings=[b"v=spf1 include:x ~all"])],
        ("_dmarc.e.com", "TXT"): [SimpleNamespace(strings=[b"v=DMARC1; p=none"])],
    }
    inspector = DnsPublicInspector(FakeDnsResolver(answers))  # type: ignore[arg-type]

    apex = await inspector.apex("e.com")

    assert apex.nameservers == ("ns1.proveedor.net",)
    assert apex.mail_hosts == ("mx.e.com",)
    assert apex.has_spf
    assert apex.has_dmarc
    assert not apex.has_caa
