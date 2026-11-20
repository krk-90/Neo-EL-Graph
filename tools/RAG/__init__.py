"""Retrieval-augmented generation helpers."""

from importlib import import_module

__all__ = ["load_docs", "chunk_docs", "store_docs", "get_chroma_store", "ingest_data"]


def __getattr__(name: str):
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    processing = import_module(".processing", __name__)
    return getattr(processing, name)
