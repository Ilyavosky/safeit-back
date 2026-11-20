from collections.abc import Mapping

from app.application.ports.testing import ToolRunner
from app.domain.entities.allowed_tool import AllowedTool
from app.domain.errors import ToolNotAllowedError


class StaticToolRegistry:
    def __init__(self, runners: Mapping[str, ToolRunner]) -> None:
        self._runners = dict(runners)

    def runner_for(self, tool: AllowedTool) -> ToolRunner:
        runner = self._runners.get(tool.name)
        if runner is None or not tool.active:
            raise ToolNotAllowedError(tool.name)
        return runner
