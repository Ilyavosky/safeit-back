from uuid import UUID


class TokenBudget:
    def __init__(self, max_tokens_per_scan: int) -> None:
        self._max = max_tokens_per_scan
        self._used: dict[UUID, int] = {}

    def has_room(self, scan_id: UUID) -> bool:
        return self._used.get(scan_id, 0) < self._max

    def spend(self, scan_id: UUID, tokens: int) -> None:
        self._used[scan_id] = self._used.get(scan_id, 0) + max(tokens, 0)

    def used(self, scan_id: UUID) -> int:
        return self._used.get(scan_id, 0)
