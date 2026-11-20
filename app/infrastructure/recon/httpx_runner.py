import asyncio
import json
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from app.application.ports.testing import ToolExecutionError
from app.domain.entities.discovered import HttpProbe
from app.domain.errors import OutOfScopeError
from app.domain.services.recon_scope import normalize_host
from app.domain.services.scope_policy import target_host
from app.infrastructure.testing.process import ProcessRunner

MAX_TECHNOLOGIES = 30
MAX_URL = 2048


class HttpxRunner:
    def __init__(self, process: ProcessRunner, binary: str = "httpx", timeout_s: int = 600) -> None:
        self._process = process
        self._binary = binary
        self._timeout_s = timeout_s

    async def probe(self, hosts: Sequence[str]) -> list[HttpProbe]:
        valid = [host for host in hosts if normalize_host(host) == host]
        if not valid:
            return []
        with tempfile.TemporaryDirectory(prefix="safeit-httpx-") as directory:
            target_file = Path(directory) / "hosts.txt"
            await asyncio.to_thread(target_file.write_text, "\n".join(valid) + "\n", "utf-8")
            args = [
                self._binary,
                "-l",
                str(target_file),
                "-json",
                "-silent",
                "-nc",
                "-td",
                "-sc",
                "-rl",
                "50",
                "-timeout",
                "10",
                "-retries",
                "1",
            ]
            result = await self._process.run(args, timeout_s=float(self._timeout_s))
        if result.returncode != 0 and not result.stdout.strip():
            raise ToolExecutionError(f"httpx terminó con código {result.returncode}.")
        return parse_httpx_output(result.stdout, set(valid))


def parse_httpx_output(output: str, allowed_hosts: set[str]) -> list[HttpProbe]:
    probes: dict[str, HttpProbe] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        probe = _to_probe(item, allowed_hosts) if isinstance(item, dict) else None
        if probe is not None:
            probes[probe.url] = probe
    return list(probes.values())


def _to_probe(item: dict[str, Any], allowed_hosts: set[str]) -> HttpProbe | None:
    url = item.get("url")
    if not isinstance(url, str) or len(url) > MAX_URL:
        return None
    try:
        host = target_host(url)
    except OutOfScopeError:
        return None
    if host not in allowed_hosts:
        return None
    status = item.get("status_code", item.get("status-code"))
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        status = None
    tech = item.get("tech", item.get("technologies", []))
    technologies = (
        tuple(str(t)[:100] for t in tech[:MAX_TECHNOLOGIES]) if isinstance(tech, list) else ()
    )
    return HttpProbe(host=host, url=url, http_status=status, technologies=technologies)
