import asyncio
import json
import ssl
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from app.application.ports.testing import ToolExecutionError
from app.domain.entities.allowed_tool import AllowedTool
from app.domain.errors import ToolNotAllowedError
from app.domain.value_objects.severity import Severity
from app.infrastructure.net.safe_http import SafeHttpClient
from app.infrastructure.testing.asyncio_scheduler import AsyncioScanScheduler
from app.infrastructure.testing.headers_runner import HeadersRunner
from app.infrastructure.testing.nuclei_runner import NucleiRunner, parse_nuclei_output
from app.infrastructure.testing.process import ProcessResult, SubprocessRunner
from app.infrastructure.testing.testssl_runner import TestsslRunner, parse_testssl_output
from app.infrastructure.testing.tool_registry import StaticToolRegistry

NUCLEI_PARAMS = {
    "tags": ["cve", "misconfig"],
    "tags_denylist": ["dos", "intrusive"],
    "rate_limit": 50,
    "timeout_s": 600,
}

NUCLEI_OUTPUT = "\n".join(
    [
        "[INF] Current nuclei version: v3.x",
        json.dumps(
            {
                "template-id": "CVE-2021-44228",
                "info": {
                    "name": "Apache Log4j RCE",
                    "severity": "critical",
                    "description": "JNDI lookup",
                    "classification": {"cve-id": ["cve-2021-44228", "no-es-cve"]},
                },
                "matched-at": "https://example.com/x",
            }
        ),
        json.dumps(
            {
                "template-id": "tech-detect",
                "info": {"name": "Detección de tecnología", "severity": "info"},
                "matched-at": "https://example.com",
                "extracted-results": ["nginx"],
            }
        ),
        json.dumps({"template-id": "odd", "info": {"severity": "unknown"}}),
        json.dumps({"sin": "info"}),
        "{roto",
    ]
)

TESTSSL_OUTPUT = json.dumps(
    [
        {"id": "scanTime", "severity": "INFO", "finding": "Scan 12 s"},
        {"id": "HSTS", "severity": "OK", "finding": "ok"},
        {
            "id": "heartbleed",
            "severity": "CRITICAL",
            "finding": "VULNERABLE",
            "cve": "CVE-2014-0160",
        },
        {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
        {
            "id": "3DES",
            "severity": "MEDIUM",
            "finding": "offered",
            "cve": "CVE-2016-2183 CVE-2016-6329, x",
        },
        {"id": "tool", "severity": "WARN", "finding": "ignorada"},
    ]
)


@dataclass
class FakeProcess:
    result: ProcessResult
    calls: list[tuple[list[str], float]] = field(default_factory=list)
    write_report: str | None = None

    async def run(self, args: Sequence[str], timeout_s: float) -> ProcessResult:
        self.calls.append((list(args), timeout_s))
        if self.write_report is not None:
            await asyncio.to_thread(
                Path(args[args.index("--jsonfile") + 1]).write_text, self.write_report, "utf-8"
            )
        return self.result


def _ok(stdout: str = "", returncode: int = 0, stderr: str = "") -> ProcessResult:
    return ProcessResult(returncode=returncode, stdout=stdout, stderr=stderr)


def test_parse_nuclei_output_extracts_findings_and_cves() -> None:
    findings = parse_nuclei_output(NUCLEI_OUTPUT)
    assert [(f.title, f.severity) for f in findings] == [
        ("Apache Log4j RCE", Severity.CRITICAL),
        ("Detección de tecnología", Severity.INFO),
        ("odd", Severity.INFO),
    ]
    assert findings[0].cve_ids == ("CVE-2021-44228",)
    assert json.loads(findings[0].evidence)["matched"] == "https://example.com/x"
    assert findings[1].cve_ids == ()


async def test_nuclei_runner_builds_a_fixed_argument_list() -> None:
    process = FakeProcess(_ok(NUCLEI_OUTPUT))
    output = await NucleiRunner(process, binary="nuclei").run("https://example.com", NUCLEI_PARAMS)
    args, timeout = process.calls[0]
    assert args[:3] == ["nuclei", "-u", "https://example.com"]
    assert args[args.index("-tags") + 1] == "cve,misconfig"
    assert args[args.index("-etags") + 1] == "dos,intrusive"
    assert args[args.index("-rl") + 1] == "50"
    assert {"-jsonl", "-silent", "-ni", "-duc"} <= set(args)
    assert timeout == 600.0
    assert len(output.findings) == 3
    assert output.raw == NUCLEI_OUTPUT


async def test_nuclei_runner_rejects_non_http_targets_and_failures() -> None:
    runner = NucleiRunner(FakeProcess(_ok()))
    for target in ("--help", "file:///etc/passwd", "example.com", "-u https://x"):
        with pytest.raises(ToolExecutionError):
            await runner.run(target, NUCLEI_PARAMS)
    failing = NucleiRunner(FakeProcess(_ok(returncode=2, stderr="boom")))
    with pytest.raises(ToolExecutionError, match="boom"):
        await failing.run("https://example.com", NUCLEI_PARAMS)
    partial = NucleiRunner(FakeProcess(_ok(NUCLEI_OUTPUT, returncode=1)))
    assert len((await partial.run("https://example.com", NUCLEI_PARAMS)).findings) == 3


def test_parse_testssl_output_keeps_only_real_problems() -> None:
    findings = parse_testssl_output(TESTSSL_OUTPUT)
    assert [(f.title, f.severity) for f in findings] == [
        ("TLS: heartbleed", Severity.CRITICAL),
        ("TLS: TLS1", Severity.LOW),
        ("TLS: 3DES", Severity.MEDIUM),
    ]
    assert findings[0].cve_ids == ("CVE-2014-0160",)
    assert findings[2].cve_ids == ("CVE-2016-2183", "CVE-2016-6329")
    assert parse_testssl_output("no json") == []
    assert parse_testssl_output('{"a": 1}') == []


async def test_testssl_runner_runs_against_host_and_port() -> None:
    process = FakeProcess(_ok(), write_report=TESTSSL_OUTPUT)
    output = await TestsslRunner(process, binary="testssl.sh").run(
        "https://Example.com:8443/login", {"timeout_s": 300}
    )
    args, timeout = process.calls[0]
    assert args[0] == "testssl.sh"
    assert args[-1] == "example.com:8443"
    assert args[args.index("--severity") + 1] == "LOW"
    assert timeout == 300.0
    assert len(output.findings) == 3


async def test_testssl_runner_validates_target_and_report() -> None:
    runner = TestsslRunner(FakeProcess(_ok()))
    for target in ("http://example.com", "https://-oX.example.com", "https://"):
        with pytest.raises(ToolExecutionError):
            await runner.run(target, {"timeout_s": 10})
    with pytest.raises(ToolExecutionError):
        await runner.run("https://example.com", {"timeout_s": 10})


@dataclass
class _Writer:
    sent: bytes = b""

    def write(self, data: bytes) -> None:
        self.sent += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None


class _Net:
    def __init__(self, addresses: list[str], response: bytes) -> None:
        self.addresses = addresses
        self.response = response
        self.connections: list[tuple[str, int]] = []
        self.writer = _Writer()

    async def resolve(self, host: str, port: int) -> list[str]:
        return self.addresses

    async def connect(
        self, ip: str, port: int, context: ssl.SSLContext | None, hostname: str | None
    ) -> tuple[asyncio.StreamReader, Any]:
        self.connections.append((ip, port))
        reader = asyncio.StreamReader()
        reader.feed_data(self.response)
        reader.feed_eof()
        return reader, self.writer


HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: session=SECRETO; Path=/\r\n"
    b"X-Content-Type-Options: nosniff\r\n\r\n<html>"
)


def _headers_runner(net: _Net) -> HeadersRunner:
    return HeadersRunner(SafeHttpClient(resolve=net.resolve, connect=net.connect, timeout=2.0))


async def test_headers_runner_analyzes_the_response_without_storing_cookie_values() -> None:
    net = _Net(["93.184.216.34"], HTTP_RESPONSE)
    output = await _headers_runner(net).run("https://example.com/app?x=1", {"timeout_s": 30})
    titles = {f.title for f in output.findings}
    assert "Falta la cabecera Content-Security-Policy" in titles
    assert "Cookie sin Secure: session" in titles
    assert "SECRETO" not in output.raw
    assert output.raw.startswith("HTTP 200")
    assert net.connections == [("93.184.216.34", 443)]
    request = net.writer.sent.decode()
    assert request.startswith("GET /app?x=1 HTTP/1.0\r\nHost: example.com\r\n")


async def test_headers_runner_refuses_private_targets_and_bad_urls() -> None:
    for address in ("127.0.0.1", "10.1.2.3", "169.254.169.254"):
        net = _Net([address], HTTP_RESPONSE)
        with pytest.raises(ToolExecutionError):
            await _headers_runner(net).run("https://example.com", {})
        assert net.connections == []
    net = _Net(["93.184.216.34"], HTTP_RESPONSE)
    for url in ("ftp://example.com", "https://user:pw@example.com", "https://a.com/\r\nX: y"):
        with pytest.raises(ToolExecutionError):
            await _headers_runner(net).run(url, {})
    garbage = _Net(["93.184.216.34"], b"no es http\r\n\r\n")
    with pytest.raises(ToolExecutionError):
        await _headers_runner(garbage).run("https://example.com", {})


async def test_subprocess_runner_uses_a_clean_environment_and_handles_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JWT_SECRET", "no-debe-llegar")
    runner = SubprocessRunner()
    import sys

    code = (
        "import os,sys;"
        "sys.stdout.write(str('JWT_SECRET' in os.environ)+'|'+str('PATH' in os.environ))"
    )
    result = await runner.run([sys.executable, "-c", code], timeout_s=20)
    assert (result.returncode, result.stdout) == (0, "False|True")
    with pytest.raises(ToolExecutionError, match="no está instalada"):
        await runner.run(["safeit-herramienta-inexistente"], timeout_s=5)
    with pytest.raises(ToolExecutionError, match="tiempo máximo"):
        await runner.run([sys.executable, "-c", "import time;time.sleep(30)"], timeout_s=0.3)


def test_registry_only_builds_registered_and_active_tools() -> None:
    sentinel: Any = object()
    registry = StaticToolRegistry({"headers": sentinel})
    active = AllowedTool(uuid4(), "headers", {}, True)
    assert registry.runner_for(active) is sentinel
    with pytest.raises(ToolNotAllowedError):
        registry.runner_for(AllowedTool(uuid4(), "sqlmap", {}, True))
    with pytest.raises(ToolNotAllowedError):
        registry.runner_for(AllowedTool(uuid4(), "headers", {}, False))


async def test_scheduler_runs_jobs_and_survives_crashes() -> None:
    scheduler = AsyncioScanScheduler()
    done: list[int] = []

    async def good() -> None:
        done.append(1)

    async def bad() -> None:
        raise RuntimeError("falla")

    scheduler.schedule(bad)
    scheduler.schedule(good)
    await scheduler.wait_idle()
    assert done == [1]

    async def forever() -> None:
        await asyncio.sleep(60)

    scheduler.schedule(forever)
    await scheduler.aclose()
    await scheduler.wait_idle()
