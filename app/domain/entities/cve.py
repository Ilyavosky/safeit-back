from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    in_cisa_kev: bool
    synced_at: datetime
