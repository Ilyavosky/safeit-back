import asyncio
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from app.application.ports.testing import ToolExecutionError
from app.domain.entities.discovered import DiscoveredService
from app.infrastructure.recon.dns_resolver import SystemHostResolver
from app.infrastructure.recon.httpx_runner import HttpxRunner, parse_httpx_output
from app.infrastructure.recon.nmap_runner import NmapRunner, parse_nmap_xml
from app.infrastructure.recon.subfinder_runner import SubfinderRunner
from app.infrastructure.testing.process import ProcessResult

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx" version="1.25.3" extrainfo="Ubuntu"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
      <port protocol="icmp" portid="1"><state state="open"/></port>
      <port protocol="tcp" portid="99999"><state state="open"/></port>
    </ports>
  </host>
  <host>
    <address addr="2606:2800:220:1:248:1893:25c8:1946" addrtype="ipv6"/>
    <ports/>
  </host>
  <host><address addr="aa:bb" addrtype="mac"/></host>
</nmaprun>"""

HTTPX_OUTPUT = "\n".join(
    [
        json.dumps({"url": "https://example.com", "status_code": 200, "tech": ["Nginx", "HSTS"]}),
        json.dumps({"url": "http://api.example.com:8080/x", "status-code": 301}),
        json.dumps({"url": "https://evil.com", "status_code": 200}),
        json.dumps({"url": "https://user:pw@example.com", "status_code": 200}),
        json.dumps({"url": "ftp://example.com"}),
        json.dumps({"status_code": 200}),
        json.dumps({"url": "https://example.com", "status_code": 404, "tech": "no-lista"}),
        "[INF] banner",
        "{roto",
    ]
)


@dataclass
class FakeProcess:
    stdout: str = ""
    returncode: int = 0
    calls: list[list[str]] = field(default_factory=list)
    file_content: str | None = None

    async def run(self, args: Sequence[str], timeout_s: float) -> ProcessResult:
        self.calls.append(list(args))
        if "-l" in args:
            path = Path(args[args.index("-l") + 1])
            self.file_content = await asyncio.to_thread(path.read_text, "utf-8")
        return ProcessResult(self.returncode, self.stdout, "")


def test_parse_nmap_keeps_open_tcp_udp_ports_and_cleans_fields() -> None:
    result = parse_nmap_xml(NMAP_XML)
    assert result == {
        "93.184.216.34": [
            DiscoveredService(80, "tcp", "http", "nginx 1.25.3", "Ubuntu"),
            DiscoveredService(443, "tcp", "https", None, None),
        ],
        "2606:2800:220:1:248:1893:25c8:1946": [],
    }


def test_parse_nmap_rejects_invalid_and_hostile_xml() -> None:
    with pytest.raises(ToolExecutionError):
        parse_nmap_xml("no es xml")
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "aaaa"><!ENTITY y "&x;&x;&x;">]>'
        "<nmaprun>&y;</nmaprun>"
    )
    with pytest.raises(ToolExecutionError):
        parse_nmap_xml(bomb)


async def test_nmap_runner_uses_fixed_arguments_and_only_public_ips() -> None:
    process = FakeProcess(stdout=NMAP_XML)
    result = await NmapRunner(process, binary="nmap").scan(["93.184.216.34"])
    args = process.calls[0]
    assert args[0] == "nmap"
    assert args[-1] == "93.184.216.34"
    assert {"-sT", "-Pn", "-n", "-oX"} <= set(args)
    assert args[args.index("--top-ports") + 1] == "100"
    assert "93.184.216.34" in result
    for bad in ("127.0.0.1", "10.0.0.1", "-oX", "example.com", "93.184.216.34; id"):
        with pytest.raises(ToolExecutionError):
            await NmapRunner(FakeProcess(stdout=NMAP_XML)).scan([bad])
    assert await NmapRunner(FakeProcess()).scan([]) == {}
    with pytest.raises(ToolExecutionError):
        await NmapRunner(FakeProcess(stdout="", returncode=1)).scan(["93.184.216.34"])


def test_parse_httpx_only_keeps_allowed_hosts_and_well_formed_urls() -> None:
    probes = parse_httpx_output(HTTPX_OUTPUT, {"example.com", "api.example.com"})
    assert [(p.host, p.url, p.http_status, p.technologies) for p in probes] == [
        ("example.com", "https://example.com", 404, ()),
        ("api.example.com", "http://api.example.com:8080/x", 301, ()),
    ]


async def test_httpx_runner_writes_validated_hosts_to_a_file() -> None:
    process = FakeProcess(stdout=HTTPX_OUTPUT)
    probes = await HttpxRunner(process, binary="httpx").probe(
        ["example.com", "-evil", "api.example.com", "http://x.com"]
    )
    assert process.file_content == "example.com\napi.example.com\n"
    assert {"-json", "-silent", "-td"} <= set(process.calls[0])
    assert len(probes) == 2
    assert await HttpxRunner(FakeProcess()).probe(["-x"]) == []
    with pytest.raises(ToolExecutionError):
        await HttpxRunner(FakeProcess(returncode=2)).probe(["example.com"])


async def test_subfinder_runner_filters_to_the_domain() -> None:
    output = (
        "api.example.com\nEXAMPLE.com\nevil.com\n*.example.com\napi.example.com\n-x.example.com\n"
    )
    process = FakeProcess(stdout=output)
    found = await SubfinderRunner(process, binary="subfinder").enumerate("example.com")
    assert found == ["api.example.com", "example.com"]
    assert process.calls[0][:3] == ["subfinder", "-d", "example.com"]
    with pytest.raises(ToolExecutionError):
        await SubfinderRunner(FakeProcess()).enumerate("-oX")
    with pytest.raises(ToolExecutionError):
        await SubfinderRunner(FakeProcess(returncode=1)).enumerate("example.com")


async def test_resolver_returns_sorted_unique_addresses_and_swallows_failures() -> None:
    async def ok(host: str, port: int) -> list[str]:
        return ["2.2.2.2", "1.1.1.1", "2.2.2.2"]

    async def failing(host: str, port: int) -> list[str]:
        raise OSError("sin DNS")

    async def slow(host: str, port: int) -> list[str]:
        await asyncio.sleep(5)
        return ["1.1.1.1"]

    assert await SystemHostResolver(ok).resolve("a.com") == ["1.1.1.1", "2.2.2.2"]
    assert await SystemHostResolver(failing).resolve("a.com") == []
    assert await SystemHostResolver(slow, timeout=0.05).resolve("a.com") == []
