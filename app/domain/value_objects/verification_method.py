from enum import StrEnum


class VerificationMethod(StrEnum):
    DNS_TXT = "dns_txt"
    FILE = "file"
