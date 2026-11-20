import asyncio
import re
import ssl
from datetime import UTC
from urllib.parse import urlsplit

import structlog
from cryptography import x509
from cryptography.x509.oid import NameOID

from app.application.ports.public_analysis import TlsObservation, WebObservation
from app.domain.services.network_safety import is_public_address
from app.infrastructure.verification.well_known_file import (
    Connect,
    Resolve,
    open_stream,
    system_resolve,
)

log = structlog.get_logger(__name__)

MAX_READ_BYTES = 65536
USER_AGENT = "SafeIT-PublicAnalysis/1.0 (analisis informativo, una sola peticion)"
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAG = re.compile(r"<[^>]+>")
_SPACES = re.compile(r"\s+")


class PublicHttpFetcher:
    def __init__(
        self,
        *,
        resolve: Resolve = system_resolve,
        connect: Connect = open_stream,
        timeout: float = 8.0,
    ) -> None:
        self._resolve = resolve
        self._connect = connect
        self._timeout = timeout

    async def fetch(self, host: str) -> WebObservation | None:
        for use_tls in (True, False):
            try:
                async with asyncio.timeout(self._timeout * 2):
                    observed = await self._fetch_once(host, use_tls)
            except (TimeoutError, OSError, ssl.SSLError, ValueError) as exc:
                log.info("public_fetch_miss", host=host, tls=use_tls, reason=type(exc).__name__)
                continue
            if observed is not None:
                return observed
        return None

    async def _fetch_once(self, host: str, use_tls: bool) -> WebObservation | None:
        port = 443 if use_tls else 80
        addresses = await self._resolve(host, port)
        if not addresses or not all(is_public_address(a) for a in addresses):
            log.info("public_fetch_blocked_address", host=host)
            return None
        if not use_tls:
            return await self._request(addresses, host, port, None, None)
        try:
            return await self._request(
                addresses, host, port, ssl.create_default_context(), valid=True
            )
        except ssl.SSLCertVerificationError:
            insecure = ssl.create_default_context()
            insecure.check_hostname = False
            insecure.verify_mode = ssl.CERT_NONE
            return await self._request(addresses, host, port, insecure, valid=False)

    async def _request(
        self,
        addresses: list[str],
        host: str,
        port: int,
        context: ssl.SSLContext | None,
        valid: bool | None,
    ) -> WebObservation | None:
        request = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Accept: text/html,*/*;q=0.5\r\nAccept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        )
        last_error: OSError | None = None
        for ip in addresses:
            try:
                reader, writer = await asyncio.wait_for(
                    self._connect(ip, port, context, host if context else None), self._timeout
                )
            except OSError as exc:
                last_error = exc
                continue
            try:
                tls = _tls_info(writer, valid) if context is not None else None
                writer.write(request.encode("ascii", errors="ignore"))
                await writer.drain()
                data = b""
                while len(data) < MAX_READ_BYTES:
                    chunk = await asyncio.wait_for(
                        reader.read(MAX_READ_BYTES - len(data)), self._timeout
                    )
                    if not chunk:
                        break
                    data += chunk
                return _parse(data, tls)
            finally:
                writer.close()
        if last_error is not None:
            raise last_error
        return None


def _tls_info(writer: asyncio.StreamWriter, valid: bool | None) -> TlsObservation | None:
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        return TlsObservation(None, bool(valid), None)
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return TlsObservation(None, bool(valid), None)
    issuer = _first(cert.issuer, NameOID.ORGANIZATION_NAME) or _first(
        cert.issuer, NameOID.COMMON_NAME
    )
    return TlsObservation(
        issuer=issuer[:120] if issuer else None,
        valid=bool(valid),
        valid_until=cert.not_valid_after_utc.astimezone(UTC),
    )


def _first(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attributes = name.get_attributes_for_oid(oid)
    if not attributes:
        return None
    value = attributes[0].value
    return value if isinstance(value, str) else value.decode("utf-8", errors="ignore")


def _parse(data: bytes, tls: TlsObservation | None) -> WebObservation | None:
    head_bytes, _, body_bytes = data.partition(b"\r\n\r\n")
    lines = head_bytes.decode("latin-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        return None
    headers = {
        name.strip(): value.strip()
        for name, sep, value in (line.partition(":") for line in lines[1:])
        if sep and name.strip()
    }
    lowered = {k.lower(): v for k, v in headers.items()}
    body = body_bytes.decode("utf-8", errors="ignore")
    return WebObservation(
        http_status=int(parts[1]),
        content_type=lowered.get("content-type", "").split(";")[0].strip() or None,
        title=_title(body),
        redirect_host=_redirect_host(lowered.get("location")),
        headers=headers,
        html_head=body[:20000],
        tls=tls,
    )


def _title(body: str) -> str | None:
    match = _TITLE.search(body)
    if match is None:
        return None
    text = _SPACES.sub(" ", _TAG.sub("", match.group(1))).strip()
    return text[:200] or None


def _redirect_host(location: str | None) -> str | None:
    if not location:
        return None
    host = urlsplit(location).hostname
    return host.lower() if host else None
