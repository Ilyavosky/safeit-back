from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class Endpoint:
    id: UUID
    asset_id: UUID
    domain_id: UUID
    url: str
    http_status: int | None
    technologies: tuple[str, ...]
    whitelisted: bool
    in_scope: bool
