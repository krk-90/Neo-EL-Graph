import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from langchain_classic.retrievers.ensemble import EnsembleRetriever
from langchain_community.retrievers import BM25Retriever
from langchain_core.documents import Document
from langchain_core.tools import tool
from langsmith import traceable

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv(dotenv_path=ROOT / ".env")

from tools.RAG.ingest.processing import get_chroma_store
from tools.RAG.Retriever.rerank import wrap_with_reranking

os.environ.setdefault("LANGSMITH_TRACING", "true")
os.environ.setdefault("LANGSMITH_PROJECT", "rag-tracing")
COLLECTION_NAME = os.environ.get("CHROMA_COLLECTION", "cve_huggingface_minilm")

if not os.environ.get("LANGSMITH_API_KEY") and not os.environ.get("LANGCHAIN_API_KEY"):
    print("[WARN] LANGSMITH_API_KEY not set — @traceable calls will not report to LangSmith.")

_bm25_docs_cache = None


@traceable(name="get vector")
def get_vector():
    return get_chroma_store(collection_name=COLLECTION_NAME)


@traceable(name="get embedded text")
def get_embedded_text(
    limit: int | None = None,
    include_embeddings: bool = False,
    batch_size: int = 100,
    verbose: bool = True,
):
    if limit is not None and limit <= 0:
        raise ValueError("limit must be greater than zero.")
    if batch_size <= 0:
        raise ValueError("batch_size must be greater than zero.")

    store = get_vector()
    collection = store._collection
    include = ["documents", "metadatas"]
    if include_embeddings:
        include.append("embeddings")

    all_ids, all_docs, all_metas, all_embeds = [], [], [], []
    offset = 0
    while True:
        batch = collection.get(limit=batch_size, offset=offset, include=include)
        if not batch["ids"]:
            break

        remaining = limit - len(all_ids) if limit is not None else batch_size
        all_ids.extend(batch["ids"][:remaining])
        all_docs.extend(batch["documents"][:remaining])
        all_metas.extend(batch["metadatas"][:remaining])
        if include_embeddings:
            all_embeds.extend(batch["embeddings"][:remaining])

        offset += len(batch["ids"])
        if limit is not None and len(all_ids) >= limit:
            break

    if verbose:
        for i, doc_id in enumerate(all_ids):
            print(f"ID: {doc_id}")
            print(f"Text: {all_docs[i][:200]}...")
            print(f"Metadata: {all_metas[i]}")
            if include_embeddings:
                print(f"Embedding (dim={len(all_embeds[i])}): {all_embeds[i][:5]}...")
            print("-" * 40)

    result = {
        "ids": all_ids,
        "documents": all_docs,
        "metadatas": all_metas,
    }
    if include_embeddings:
        result["embeddings"] = all_embeds
    return result


@traceable(name="get BM25 docs")
def _get_bm25_docs(force_refresh: bool = False):
    global _bm25_docs_cache
    if _bm25_docs_cache is None or force_refresh:
        stored = get_embedded_text(verbose=False)
        _bm25_docs_cache = [
            Document(page_content=text, metadata=meta)
            for text, meta in zip(stored["documents"], stored["metadatas"])
        ]
    return _bm25_docs_cache


@traceable(name="retrieve and rerank")
def retrieve(
    k: int = 4,
    refresh_bm25: bool = False,
    fetch_k: int | None = None,
    rerank: bool = True,
):
    if k <= 0:
        raise ValueError("k must be greater than zero.")
    if fetch_k is None:
        fetch_k = max(4 * k, 20)
    if fetch_k <= 0:
        raise ValueError("fetch_k must be greater than zero.")

    store = get_vector()
    collection_count = store._collection.count()
    if collection_count == 0:
        raise RuntimeError(
            "The Chroma collection is empty. Index CVEs first with "
            "`python -m tools.RAG.processing`."
        )

    retriever = store.as_retriever(search_kwargs={"k": fetch_k if rerank else k})
    bm25_docs = _get_bm25_docs(force_refresh=refresh_bm25)
    bm25 = BM25Retriever.from_documents(bm25_docs)
    bm25.k = fetch_k if rerank else k

    ensemble_retriever = EnsembleRetriever(
        retrievers=[retriever, bm25],
        weights=[0.4, 0.6],
    )
    if not rerank:
        return ensemble_retriever
    return wrap_with_reranking(ensemble_retriever, top_n=k)


@tool
def search_cves(query: str, limit: int = 5, severity: str | None = None) -> list[dict]:
    """Search indexed CVEs by meaning, optionally filtering by severity.

    Returns matching CVE text and metadata including CVE ID, severity, and CVSS.
    """
    if not query.strip():
        raise ValueError("query must not be empty.")
    if not 1 <= limit <= 20:
        raise ValueError("limit must be between 1 and 20.")

    search_filter = None
    if severity is not None:
        normalized_severity = severity.strip().upper()
        if normalized_severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
            raise ValueError(
                "severity must be CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN."
            )
        search_filter = {"severity": normalized_severity}

    documents = get_vector().similarity_search(
        query,
        k=limit,
        filter=search_filter,
    )
    return [
        {
            "cve_id": document.metadata.get("cve_id"),
            "severity": document.metadata.get("severity"),
            "cvss_score": document.metadata.get("cvss_score"),
            "content": document.page_content,
        }
        for document in documents
    ]


def main():
    parser = argparse.ArgumentParser(description="Query or inspect the RAG vector store")
    parser.add_argument("--query", type=str, help="Query text to retrieve relevant chunks for")
    parser.add_argument("--k", type=int, default=4, help="Number of final results after reranking (default: 4)")
    parser.add_argument("--fetch-k", type=int, default=None,
                        help="Number of candidates to fetch from vector+BM25 before reranking (default: 4*k, min 20)")
    parser.add_argument("--no-rerank", action="store_true",
                        help="Disable reranking and return raw ensemble retriever results")
    parser.add_argument("--refresh-bm25", action="store_true",
                        help="Force-refresh the BM25 index from Chroma before querying")
    parser.add_argument("--inspect", action="store_true",
                        help="Print stored documents/metadata instead of running a query")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit number of documents fetched when using --inspect")
    parser.add_argument("--json", action="store_true",
                        help="Output retrieved results as JSON instead of pretty-printed text")
    args = parser.parse_args()

    if args.inspect:
        get_embedded_text(limit=args.limit, verbose=True)
        return
    if not args.query:
        parser.error("--query is required unless --inspect is set")

    retriever = retrieve(
        k=args.k,
        refresh_bm25=args.refresh_bm25,
        fetch_k=args.fetch_k,
        rerank=not args.no_rerank,
    )
    results = retriever.invoke(args.query)
    if args.json:
        payload = [
            {"content": doc.page_content, "metadata": doc.metadata}
            for doc in results
        ]
        print(json.dumps(payload, indent=2))
    else:
        for i, doc in enumerate(results, start=1):
            print(f"[{i}] {doc.metadata}")
            print(doc.page_content[:300].strip())
            print("-" * 40)


if __name__ == "__main__":
    main()
