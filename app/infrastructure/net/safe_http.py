import asyncio
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.application.ports.testing import ToolExecutionError
from app.domain.errors import OutOfScopeError
from app.domain.services.network_safety import is_public_address
from app.domain.services.scope_policy import target_host
from app.infrastructure.verification.well_known_file import (
    Connect,
    Resolve,
    open_stream,
    system_resolve,
)

MAX_HEAD_BYTES = 32768


@dataclass(frozen=True)
class HttpHead:
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]


class SafeHttpClient:
    def __init__(
        self,
        *,
        resolve: Resolve = system_resolve,
        connect: Connect = open_stream,
        timeout: float = 10.0,
    ) -> None:
        self._resolve = resolve
        self._connect = connect
        self._timeout = timeout

    async def get_head(self, url: str) -> HttpHead:
        if "\r" in url or "\n" in url:
            raise ToolExecutionError("La URL contiene caracteres no válidos.")
        try:
            host = target_host(url)
        except OutOfScopeError as exc:
            raise ToolExecutionError(exc.message) from exc
        parts = urlsplit(url)
        use_tls = parts.scheme == "https"
        port = parts.port or (443 if use_tls else 80)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        try:
            async with asyncio.timeout(self._timeout):
                addresses = await self._resolve(host, port)
                if not addresses or not all(is_public_address(a) for a in addresses):
                    raise ToolExecutionError("El objetivo resuelve a una dirección no pública.")
                data = await self._request(addresses, host, port, use_tls, path)
        except TimeoutError as exc:
            raise ToolExecutionError("La petición superó el tiempo máximo.") from exc
        except ssl.SSLError as exc:
            raise ToolExecutionError("El certificado TLS del objetivo no es válido.") from exc
        except OSError as exc:
            raise ToolExecutionError("No se pudo conectar con el objetivo.") from exc
        return _parse_head(url, data)

    async def _request(
        self, addresses: list[str], host: str, port: int, use_tls: bool, path: str
    ) -> bytes:
        context = ssl.create_default_context() if use_tls else None
        default_port = 443 if use_tls else 80
        host_header = host if port == default_port else f"{host}:{port}"
        request = (
            f"GET {path} HTTP/1.0\r\nHost: {host_header}\r\nUser-Agent: SafeIT-Scanner/1.0\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        )
        last_error: OSError | None = None
        for ip in addresses:
            try:
                reader, writer = await self._connect(ip, port, context, host if use_tls else None)
            except OSError as exc:
                last_error = exc
                continue
            try:
                writer.write(request.encode("ascii", errors="ignore"))
                await writer.drain()
                data = b""
                while len(data) < MAX_HEAD_BYTES and b"\r\n\r\n" not in data:
                    chunk = await reader.read(MAX_HEAD_BYTES - len(data))
                    if not chunk:
                        break
                    data += chunk
                return data
            finally:
                writer.close()
        raise last_error or OSError("sin direcciones")


def _parse_head(url: str, data: bytes) -> HttpHead:
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    status_parts = lines[0].split()
    if (
        len(status_parts) < 2
        or not status_parts[0].startswith("HTTP/")
        or not status_parts[1].isdigit()
    ):
        raise ToolExecutionError("La respuesta del objetivo no es HTTP válido.")
    headers = tuple(
        (name.strip(), value.strip())
        for name, separator, value in (line.partition(":") for line in lines[1:])
        if separator and name.strip()
    )
    return HttpHead(url=url, status=int(status_parts[1]), headers=headers)
