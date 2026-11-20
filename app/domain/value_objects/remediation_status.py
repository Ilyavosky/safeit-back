from enum import StrEnum


class RemediationStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
