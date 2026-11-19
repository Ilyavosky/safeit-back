from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.domain.value_objects.asset_kind import AssetKind


@dataclass(frozen=True)
class Asset:
    id: UUID
    domain_id: UUID
    scan_id: UUID
    kind: AssetKind
    value: str
    in_scope: bool
    discovered_at: datetime
