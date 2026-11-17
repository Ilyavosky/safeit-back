import secrets

TOKEN_PREFIX = "safeit-verification="  # noqa: S105
DNS_LABEL = "_safeit-verify"


def new_verification_token() -> str:
    return TOKEN_PREFIX + secrets.token_hex(16)


def dns_record_name(domain_name: str) -> str:
    return f"{DNS_LABEL}.{domain_name}"


def file_path(token: str) -> str:
    return f"/.well-known/safeit-{token.removeprefix(TOKEN_PREFIX)}.txt"
