from collections.abc import Mapping
from typing import Any

from app.application.ports.testing import ToolOutput
from app.domain.services.header_analysis import analyze_headers
from app.infrastructure.net.safe_http import SafeHttpClient


class HeadersRunner:
    def __init__(self, http: SafeHttpClient) -> None:
        self._http = http

    async def run(self, url: str, params: Mapping[str, Any]) -> ToolOutput:
        head = await self._http.get_head(url)
        lines = [f"HTTP {head.status}"]
        for name, value in head.headers:
            shown = value.split("=", 1)[0] + "=<oculto>" if name.lower() == "set-cookie" else value
            lines.append(f"{name}: {shown}")
        return ToolOutput(findings=analyze_headers(url, head.headers), raw="\n".join(lines))
