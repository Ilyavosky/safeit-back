from collections.abc import Sequence

from app.domain.entities.endpoint import Endpoint
from app.domain.entities.planned_test import PlannedTest
from app.domain.services.test_planning import plan_tests


class FixedProbePlanner:
    def plan(self, endpoints: Sequence[Endpoint]) -> list[PlannedTest]:
        return plan_tests(endpoints)
