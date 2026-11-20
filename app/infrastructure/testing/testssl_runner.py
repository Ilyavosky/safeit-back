import json
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.application.ports.testing import ToolExecutionError, ToolOutput
from app.domain.entities.raw_finding import RawFinding
from app.domain.errors import InvalidCveIdError
from app.domain.services.cve_id import normalize_cve_id
from app.domain.value_objects.severity import Severity
from app.infrastructure.testing.process import ProcessRunner

MAX_TITLE = 255
MAX_EVIDENCE = 4000
_HOST = re.compile(r"[a-z0-9][a-z0-9.-]*")
_SEVERITIES = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


class TestsslRunner:
    __test__ = False

    def __init__(self, process: ProcessRunner, binary: str = "testssl.sh") -> None:
        self._process = process
        self._binary = binary

    async def run(self, url: str, params: Mapping[str, Any]) -> ToolOutput:
        target = _tls_target(url)
        with tempfile.TemporaryDirectory(prefix="safeit-testssl-") as directory:
            report = Path(directory) / "report.json"
            args = [
                self._binary,
                "--jsonfile",
                str(report),
                "--severity",
                "LOW",
                "--color",
                "0",
                "--warnings",
                "off",
                "--quiet",
                "--connect-timeout",
                "10",
                target,
            ]
            result = await self._process.run(args, timeout_s=float(params["timeout_s"]))
            if not report.exists():
                detail = result.stderr.strip()[:200]
                raise ToolExecutionError(f"testssl no generó resultados: {detail}")
            raw = report.read_text(encoding="utf-8", errors="replace")
        return ToolOutput(findings=parse_testssl_output(raw), raw=raw)


def _tls_target(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or _HOST.fullmatch(host) is None:
        raise ToolExecutionError("testssl solo acepta URL https con un host válido.")
    return f"{host}:{parts.port or 443}"


def parse_testssl_output(raw: str) -> list[RawFinding]:
    try:
        entries = json.loads(raw)
    except ValueError:
        return []
    if not isinstance(entries, list):
        return []
    findings: list[RawFinding] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        severity = _SEVERITIES.get(str(entry.get("severity", "")).upper())
        identifier = entry.get("id")
        if severity is None or not isinstance(identifier, str):
            continue
        detail = str(entry.get("finding", "")).strip()
        findings.append(
            RawFinding(
                title=f"TLS: {identifier}"[:MAX_TITLE],
                severity=severity,
                evidence=f"{identifier}: {detail}"[:MAX_EVIDENCE],
                cve_ids=_cve_ids(entry.get("cve")),
            )
        )
    return findings


def _cve_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, str):
        return ()
    found: dict[str, None] = {}
    for token in re.split(r"[\s,;]+", value):
        try:
            found[normalize_cve_id(token)] = None
        except InvalidCveIdError:
            continue
    return tuple(found)
