import re

from app.domain.errors import InvalidCveIdError

_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
MAX_CVE_ID_LENGTH = 20


def normalize_cve_id(raw: str) -> str:
    cve_id = raw.strip().upper()
    if len(cve_id) > MAX_CVE_ID_LENGTH or _CVE_ID.fullmatch(cve_id) is None:
        raise InvalidCveIdError
    return cve_id
