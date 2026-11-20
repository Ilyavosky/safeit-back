from enum import StrEnum


class FindingLifecycle(StrEnum):
    DISCOVERED = "discovered"
    IN_ANALYSIS = "in_analysis"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    IN_REMEDIATION = "in_remediation"
    RESOLVED = "resolved"
