from uuid import UUID

from app.application.ports.repositories import DomainRepository
from app.application.ports.testing_repositories import ScanRepository
from app.application.use_cases.domains.access import load_domain
from app.domain.entities.domain import Domain
from app.domain.entities.scan import Scan
from app.domain.entities.user import User
from app.domain.errors import EntityNotFoundError


async def load_scan(
    domains: DomainRepository, scans: ScanRepository, user: User, scan_id: UUID
) -> tuple[Scan, Domain]:
    scan = await scans.get(scan_id)
    if scan is None:
        raise EntityNotFoundError("scan", scan_id)
    domain = await load_domain(domains, user, scan.domain_id, owner_only=False)
    return scan, domain
