from datetime import datetime

from pydantic import BaseModel

from app.domain.entities.cve import CveRecord
from app.domain.services.risk_scoring import priority_score


class CveResponse(BaseModel):
    cve_id: str
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    in_cisa_kev: bool
    priority_score: float | None
    synced_at: datetime

    @classmethod
    def from_record(cls, record: CveRecord) -> "CveResponse":
        return cls(
            cve_id=record.cve_id,
            cvss_score=record.cvss_score,
            cvss_vector=record.cvss_vector,
            epss_score=record.epss_score,
            in_cisa_kev=record.in_cisa_kev,
            priority_score=priority_score(record.cvss_score, record.epss_score, record.in_cisa_kev),
            synced_at=record.synced_at,
        )
