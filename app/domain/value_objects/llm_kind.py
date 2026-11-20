from enum import StrEnum


class LlmKind(StrEnum):
    PLAN = "plan"
    CORRELATION = "correlation"
    FALSE_POSITIVE = "false_positive"
    REPORT = "report"
