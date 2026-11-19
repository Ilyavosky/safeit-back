from dataclasses import dataclass

from app.domain.value_objects.severity import Severity


@dataclass(frozen=True)
class RawFinding:
    title: str
    severity: Severity
    evidence: str
    cve_ids: tuple[str, ...] = ()
