from collections.abc import Sequence
from urllib.parse import urlsplit

from app.domain.entities.endpoint import Endpoint
from app.domain.entities.planned_test import PlannedTest

NUCLEI_TAGS = ("cve", "exposure", "misconfig", "tech")


def plan_tests(endpoints: Sequence[Endpoint]) -> list[PlannedTest]:
    plan: list[PlannedTest] = []
    tls_targets: set[tuple[str, int]] = set()
    for endpoint in sorted(endpoints, key=lambda e: (e.url, str(e.id))):
        plan.append(PlannedTest(endpoint.id, "headers"))
        target = _tls_target(endpoint.url)
        if target is not None and target not in tls_targets:
            tls_targets.add(target)
            plan.append(PlannedTest(endpoint.id, "testssl"))
        plan.append(PlannedTest(endpoint.id, "nuclei", {"tags": list(NUCLEI_TAGS)}))
    return plan


def _tls_target(url: str) -> tuple[str, int] | None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return None
    return parts.hostname.lower(), parts.port or 443
