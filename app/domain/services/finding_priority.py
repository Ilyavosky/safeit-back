from collections.abc import Sequence

from app.domain.value_objects.severity import Severity

SEVERITY_BASELINE: dict[Severity, float] = {
    Severity.INFO: 5.0,
    Severity.LOW: 20.0,
    Severity.MEDIUM: 45.0,
    Severity.HIGH: 70.0,
    Severity.CRITICAL: 90.0,
}


def finding_priority(severity: Severity, cve_priorities: Sequence[float]) -> float:
    if cve_priorities:
        return round(max(cve_priorities), 2)
    return SEVERITY_BASELINE[severity]
