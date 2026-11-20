import asyncio
import contextlib
import socket
import ssl
from collections.abc import Awaitable, Callable

import structlog

from app.domain.services.domain_verification import file_path
from app.domain.services.network_safety import is_public_address

log = structlog.get_logger(__name__)

MAX_RESPONSE_BYTES = 8192
USER_AGENT = "SafeIT-Verifier/1.0"

Resolve = Callable[[str, int], Awaitable[list[str]]]
Connect = Callable[
    [str, int, ssl.SSLContext | None, str | None],
    Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]


async def system_resolve(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


async def open_stream(
    ip: str, port: int, context: ssl.SSLContext | None, server_hostname: str | None
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(ip, port, ssl=context, server_hostname=server_hostname)


class WellKnownFileVerifier:
    def __init__(
        self,
        *,
        resolve: Resolve = system_resolve,
        connect: Connect = open_stream,
        timeout: float = 5.0,
    ) -> None:
        self._resolve = resolve
        self._connect = connect
        self._timeout = timeout

    async def check(self, name: str, token: str) -> bool:
        path = file_path(token)
        for use_tls, port in ((True, 443), (False, 80)):
            if await self._matches(name, port, use_tls, path, token):
                return True
        return False

    async def _matches(self, name: str, port: int, use_tls: bool, path: str, token: str) -> bool:
        try:
            async with asyncio.timeout(self._timeout):
                addresses = await self._resolve(name, port)
                if not addresses or not all(is_public_address(a) for a in addresses):
                    log.warning("domain_verification_blocked_address", domain=name)
                    return False
                body = await self._fetch(addresses, name, port, use_tls, path)
        except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
            log.info("file_verification_miss", domain=name, reason=type(exc).__name__)
            return False
        return body is not None and token in body

    async def _fetch(
        self, addresses: list[str], name: str, port: int, use_tls: bool, path: str
    ) -> str | None:
        context = ssl.create_default_context() if use_tls else None
        hostname = name if use_tls else None
        last_error: OSError | None = None
        for ip in addresses:
            try:
                reader, writer = await self._connect(ip, port, context, hostname)
            except OSError as exc:
                last_error = exc
                continue
            try:
                return await _get(reader, writer, name, path)
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
        if last_error is not None:
            raise last_error
        return None


async def _get(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, path: str
) -> str | None:
    request = (
        f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
        "Accept: text/plain\r\nConnection: close\r\n\r\n"
    )
    writer.write(request.encode("ascii"))
    await writer.drain()
    data = b""
    while len(data) < MAX_RESPONSE_BYTES:
        chunk = await reader.read(MAX_RESPONSE_BYTES - len(data))
        if not chunk:
            break
        data += chunk
    head, separator, body = data.partition(b"\r\n\r\n")
    if not separator:
        return None
    status_line = head.split(b"\r\n", 1)[0].split()
    if len(status_line) < 2 or status_line[1] != b"200":
        return None
    return body.decode("utf-8", errors="ignore")
