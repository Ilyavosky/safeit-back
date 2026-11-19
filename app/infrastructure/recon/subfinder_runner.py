from app.application.ports.testing import ToolExecutionError
from app.domain.services.recon_scope import normalize_host
from app.domain.services.scope_policy import is_host_in_domain
from app.infrastructure.testing.process import ProcessRunner

MAX_SUBDOMAINS = 2000


class SubfinderRunner:
    def __init__(self, process: ProcessRunner, binary: str = "subfinder", timeout_s: int = 300):
        self._process = process
        self._binary = binary
        self._timeout_s = timeout_s

    async def enumerate(self, domain: str) -> list[str]:
        if normalize_host(domain) != domain:
            raise ToolExecutionError("El dominio no es válido para subfinder.")
        args = [self._binary, "-d", domain, "-silent", "-nc", "-timeout", "30", "-max-time", "4"]
        result = await self._process.run(args, timeout_s=float(self._timeout_s))
        if result.returncode != 0 and not result.stdout.strip():
            raise ToolExecutionError(f"subfinder terminó con código {result.returncode}.")
        found: dict[str, None] = {}
        for line in result.stdout.splitlines():
            host = normalize_host(line)
            if host is not None and is_host_in_domain(host, domain):
                found[host] = None
            if len(found) >= MAX_SUBDOMAINS:
                break
        return list(found)
