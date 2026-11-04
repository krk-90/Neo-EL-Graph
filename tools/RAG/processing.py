"""High-level helpers for loading, chunking, and storing RAG data."""

import argparse

from tools.RAG.ingest.processing import (
    COLLECTION_NAME,
    DEFAULT_DATA_PATH,
    chunk_docs,
    get_chroma_store,
    ingest_data,
    load_docs,
    store_docs,
)

__all__ = [
    "COLLECTION_NAME",
    "DEFAULT_DATA_PATH",
    "load_docs",
    "chunk_docs",
    "store_docs",
    "get_chroma_store",
    "ingest_data",
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Embed CVE records with Hugging Face and index them in Chroma."
    )
    parser.add_argument(
        "--input",
        default=str(DEFAULT_DATA_PATH),
        help="Path to CVE JSONL input (default: filtered NVD records).",
    )
    parser.add_argument(
        "--collection",
        default=COLLECTION_NAME,
        help="Chroma collection name.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Number of CVE chunks to embed per batch.",
    )
    args = parser.parse_args()

    store = ingest_data(
        path=args.input,
        collection_name=args.collection,
        batch_size=args.batch_size,
    )
    print(
        f"Indexed CVE chunks in collection '{args.collection}'. "
        f"Collection size: {store._collection.count()}."
    )


if __name__ == "__main__":
    main()
