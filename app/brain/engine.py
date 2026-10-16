from uuid import uuid4
from .reasoner import GroundedReasoner
from .store import BrainStore


class BrainEngine:
    """Coordinates retrieval, grounded reasoning, and persistent investigation records."""

    def __init__(self, store: BrainStore | None = None, reasoner: GroundedReasoner | None = None) -> None:
        self.store = store or BrainStore()
        self.reasoner = reasoner or GroundedReasoner()

    def investigate(self, query: str, entity_ids: list[str], max_hops: int, include_unverified: bool) -> dict:
        result = self.store.investigate(str(uuid4()), query, entity_ids, max_hops, include_unverified)
        result["reasoning"] = self.reasoner.analyze(query, result)
        return result
