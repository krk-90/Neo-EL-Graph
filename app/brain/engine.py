from uuid import uuid4
from .store import BrainStore


class BrainEngine:
    """Coordinates graph retrieval and records results; LLM reasoning can be added behind this boundary."""

    def __init__(self, store: BrainStore | None = None) -> None:
        self.store = store or BrainStore()

    def investigate(self, query: str, entity_ids: list[str], max_hops: int, include_unverified: bool) -> dict:
        return self.store.investigate(str(uuid4()), query, entity_ids, max_hops, include_unverified)
