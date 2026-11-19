import ipaddress
import re
from collections.abc import Sequence
from xml.etree.ElementTree import Element

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from app.application.ports.testing import ToolExecutionError
from app.domain.entities.discovered import DiscoveredService
from app.domain.services.network_safety import is_public_address
from app.infrastructure.testing.process import ProcessRunner

MAX_FIELD = 500
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class NmapRunner:
    def __init__(self, process: ProcessRunner, binary: str = "nmap", timeout_s: int = 600) -> None:
        self._process = process
        self._binary = binary
        self._timeout_s = timeout_s

    async def scan(self, addresses: Sequence[str]) -> dict[str, list[DiscoveredService]]:
        targets = [_validated(address) for address in addresses]
        if not targets:
            return {}
        args = [
            self._binary,
            "-sT",
            "-Pn",
            "-n",
            "-sV",
            "--version-light",
            "--top-ports",
            "100",
            "-T3",
            "--max-retries",
            "1",
            "--host-timeout",
            "300s",
            "-oX",
            "-",
            *targets,
        ]
        result = await self._process.run(args, timeout_s=float(self._timeout_s))
        if not result.stdout.strip():
            raise ToolExecutionError(f"nmap no devolvió resultados (código {result.returncode}).")
        return parse_nmap_xml(result.stdout)


def _validated(address: str) -> str:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ToolExecutionError("Dirección IP no válida para nmap.") from exc
    if not is_public_address(str(parsed)):
        raise ToolExecutionError("nmap solo escanea direcciones públicas.")
    return str(parsed)


def _clean(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = _CONTROL.sub("", value).strip()[:MAX_FIELD]
    return cleaned or None


def parse_nmap_xml(xml: str) -> dict[str, list[DiscoveredService]]:
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise ToolExecutionError("La salida de nmap no es XML válido.") from exc
    results: dict[str, list[DiscoveredService]] = {}
    for host in root.iter("host"):
        address = _address(host)
        if address is None:
            continue
        services = [s for port in host.iter("port") if (s := _service(port)) is not None]
        results[address] = services
    return results


def _address(host: Element) -> str | None:
    for node in host.findall("address"):
        if node.get("addrtype") in {"ipv4", "ipv6"}:
            return node.get("addr")
    return None


def _service(port: Element) -> DiscoveredService | None:
    state = port.find("state")
    if state is None or state.get("state") != "open":
        return None
    protocol = port.get("protocol")
    raw_port = port.get("portid", "")
    if protocol not in {"tcp", "udp"} or not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
        return None
    node = port.find("service")
    name = version = banner = None
    if node is not None:
        name = _clean(node.get("name"))
        version = _clean(" ".join(filter(None, [node.get("product"), node.get("version")])))
        banner = _clean(node.get("extrainfo"))
    return DiscoveredService(int(raw_port), protocol, name, version, banner)
