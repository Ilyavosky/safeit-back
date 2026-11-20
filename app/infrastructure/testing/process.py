import asyncio
import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from app.application.ports.testing import ToolExecutionError

MAX_OUTPUT_BYTES = 2_000_000
PASSTHROUGH_ENV = ("PATH", "HOME", "LANG", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "USERPROFILE")


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


class ProcessRunner(Protocol):
    async def run(self, args: Sequence[str], timeout_s: float) -> ProcessResult: ...


class SubprocessRunner:
    async def run(self, args: Sequence[str], timeout_s: float) -> ProcessResult:
        env = {key: os.environ[key] for key in PASSTHROUGH_ENV if key in os.environ}
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError as exc:
            raise ToolExecutionError(f"La herramienta {args[0]} no está instalada.") from exc
        except OSError as exc:
            raise ToolExecutionError(f"No se pudo iniciar {args[0]}.") from exc
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout_s)
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise ToolExecutionError("La herramienta superó el tiempo máximo.") from exc
        return ProcessResult(
            returncode=process.returncode if process.returncode is not None else -1,
            stdout=stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"),
            stderr=stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"),
        )
