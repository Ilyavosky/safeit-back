import json
import re
from collections.abc import Mapping
from typing import Any

from app.application.ports.testing import ToolExecutionError, ToolOutput
from app.domain.entities.raw_finding import RawFinding
from app.domain.errors import InvalidCveIdError
from app.domain.services.cve_id import normalize_cve_id
from app.domain.value_objects.severity import Severity
from app.infrastructure.testing.process import ProcessRunner

MAX_TITLE = 255
MAX_EVIDENCE = 4000
_CVE_IN_TEXT = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.IGNORECASE)


class NucleiRunner:
    def __init__(self, process: ProcessRunner, binary: str = "nuclei") -> None:
        self._process = process
        self._binary = binary

    async def run(self, url: str, params: Mapping[str, Any]) -> ToolOutput:
        if not url.startswith(("http://", "https://")):
            raise ToolExecutionError("nuclei solo acepta URL http o https.")
        args = [
            self._binary,
            "-u",
            url,
            "-tags",
            ",".join(params["tags"]),
            "-etags",
            ",".join(params["tags_denylist"]),
            "-rl",
            str(params["rate_limit"]),
            "-jsonl",
            "-silent",
            "-nc",
            "-ni",
            "-duc",
            "-timeout",
            "10",
            "-retries",
            "1",
        ]
        result = await self._process.run(args, timeout_s=float(params["timeout_s"]))
        if result.returncode != 0 and not result.stdout.strip():
            detail = result.stderr.strip()[:200]
            raise ToolExecutionError(f"nuclei terminó con código {result.returncode}: {detail}")
        return ToolOutput(findings=parse_nuclei_output(result.stdout), raw=result.stdout)


def parse_nuclei_output(output: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        finding = _to_finding(item) if isinstance(item, dict) else None
        if finding is not None:
            findings.append(finding)
    return findings


def _to_finding(item: dict[str, Any]) -> RawFinding | None:
    info = item.get("info")
    template_id = item.get("template-id")
    if not isinstance(info, dict) or not isinstance(template_id, str):
        return None
    name = info.get("name") if isinstance(info.get("name"), str) else template_id
    evidence = {
        "template": template_id,
        "matched": item.get("matched-at") or item.get("host"),
        "description": info.get("description"),
        "extracted": item.get("extracted-results"),
    }
    return RawFinding(
        title=str(name)[:MAX_TITLE],
        severity=_severity(info.get("severity")),
        evidence=json.dumps({k: v for k, v in evidence.items() if v}, ensure_ascii=False)[
            :MAX_EVIDENCE
        ],
        cve_ids=_cve_ids(template_id, info.get("classification")),
    )


def _severity(value: object) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.INFO


def _cve_ids(template_id: str, classification: object) -> tuple[str, ...]:
    candidates: list[str] = _CVE_IN_TEXT.findall(template_id)
    if isinstance(classification, dict):
        raw = classification.get("cve-id")
        values = raw if isinstance(raw, list) else [raw]
        candidates.extend(str(value) for value in values if value)
    found: dict[str, None] = {}
    for candidate in candidates:
        try:
            found[normalize_cve_id(candidate)] = None
        except InvalidCveIdError:
            continue
    return tuple(found)
