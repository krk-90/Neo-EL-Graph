"""Run the dependency-light retrieval benchmark and write JSON metrics."""
from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from tools.RAG.Evaluation.evaluate import GOLDEN_PATH, load_jsonl
from tools.RAG.Evaluation.metrics import (
    aggregate,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
)
from tools.RAG.Retriever.retrieval import get_embedded_text, retrieve


def evaluate_retrieval(golden: dict[str, dict], k: int = 5) -> dict:
    if k <= 0:
        raise ValueError("k must be greater than zero")

    retriever = retrieve(k=k)
    stored = get_embedded_text(verbose=False)
    indexed_ids = {
        str(metadata.get("cve_id"))
        for metadata in stored["metadatas"]
        if metadata.get("cve_id")
    }
    cases = []

    for case_id, expected in golden.items():
        relevant = set(expected.get("relevant_ids", []))
        documents = retriever.invoke(expected["question"])
        retrieved_ids = [
            str(document.metadata.get("cve_id"))
            for document in documents[:k]
            if document.metadata.get("cve_id")
        ]
        indexed_ids.update(retrieved_ids)

        case = {
            "id": case_id,
            "question": expected["question"],
            "relevant_ids": sorted(relevant),
            "retrieved_ids": retrieved_ids,
            "precision@k": precision_at_k(retrieved_ids, relevant, k),
            "recall@k": recall_at_k(retrieved_ids, relevant, k),
            "mrr": reciprocal_rank(retrieved_ids, relevant),
            "ndcg@k": ndcg_at_k(retrieved_ids, relevant, k),
            "no_answer_case": not relevant,
        }
        if relevant:
            case["index_coverage"] = {
                cve_id: cve_id in indexed_ids for cve_id in relevant
            }
        cases.append(case)

    relevant_cases = [case for case in cases if case["relevant_ids"]]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": platform.python_version(),
            "executable": sys.executable,
        },
        "configuration": {
            "k": k,
            "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
            "retrieval": "hybrid vector + BM25 + reranking",
            "golden_dataset": str(GOLDEN_PATH),
        },
        "cases": cases,
        "aggregate": {
            "cases": len(golden),
            "relevant_cases": len(relevant_cases),
            "precision@k": aggregate([case["precision@k"] for case in relevant_cases]),
            "recall@k": aggregate([case["recall@k"] for case in relevant_cases]),
            "mrr": aggregate([case["mrr"] for case in relevant_cases]),
            "ndcg@k": aggregate([case["ndcg@k"] for case in relevant_cases]),
        },
    }

    recall = report["aggregate"]["recall@k"]
    report["assessment"] = (
        "strong" if recall >= 0.70
        else "moderate" if recall >= 0.40
        else "weak"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Neo-EL-Graph retrieval")
    parser.add_argument("--golden", type=Path, default=GOLDEN_PATH)
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "retrieval_metrics.json",
    )
    args = parser.parse_args()

    report = evaluate_retrieval(load_jsonl(args.golden), args.k)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
