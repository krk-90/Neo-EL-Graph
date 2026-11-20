"""Offline evaluator for JSONL golden cases and model predictions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.RAG.Evaluation.metrics import (
    aggregate,
    citation_coverage,
    exact_match,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
    token_f1,
)

HERE = Path(__file__).resolve().parent
GOLDEN_PATH = HERE / "golden_dataset.jsonl"

def load_jsonl(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip(): continue
            try: row = json.loads(line)
            except json.JSONDecodeError as exc: raise ValueError(f"Invalid JSON on line {line_number}: {path}") from exc
            if not isinstance(row, dict) or not row.get("id"): raise ValueError(f"Each row needs an id (line {line_number})")
            if row["id"] in rows: raise ValueError(f"Duplicate evaluation id: {row['id']}")
            rows[row["id"]] = row
    return rows

def evaluate(golden: dict[str, dict], predictions: dict[str, dict], k: int = 5) -> dict:
    if k <= 0: raise ValueError("k must be greater than zero")
    missing = sorted(set(golden) - set(predictions))
    unknown = sorted(set(predictions) - set(golden))
    if missing: raise ValueError("Missing predictions for: " + ", ".join(missing))
    metrics = {name: [] for name in ("precision", "recall", "mrr", "ndcg", "exact_match", "token_f1", "citation_coverage")}
    for case_id, expected in golden.items():
        actual = predictions[case_id]
        retrieved = actual.get("retrieved_ids", [])
        relevant = set(expected.get("relevant_ids", []))
        answer, reference = actual.get("answer", ""), expected.get("reference_answer", "")
        metrics["precision"].append(precision_at_k(retrieved, relevant, k))
        metrics["recall"].append(recall_at_k(retrieved, relevant, k))
        metrics["mrr"].append(reciprocal_rank(retrieved, relevant))
        metrics["ndcg"].append(ndcg_at_k(retrieved, relevant, k))
        metrics["exact_match"].append(exact_match(answer, reference))
        metrics["token_f1"].append(token_f1(answer, reference))
        metrics["citation_coverage"].append(citation_coverage(answer, set(expected.get("expected_citations", []))))
    return {
        "cases": len(golden), "k": k,
        "retrieval": {f"precision@{k}": aggregate(metrics["precision"]), f"recall@{k}": aggregate(metrics["recall"]), "mrr": aggregate(metrics["mrr"]), f"ndcg@{k}": aggregate(metrics["ndcg"])},
        "generation": {name: aggregate(metrics[name]) for name in ("exact_match", "token_f1", "citation_coverage")},
        "missing_prediction_ids": missing, "unknown_prediction_ids": unknown,
        "notes": ["Exact match and token F1 are lexical baselines, not semantic correctness.", "Add human review and optional RAGAS faithfulness/context precision/context recall.", "Inspect per-case failures; do not use one aggregate score as a release gate."]
    }

def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Neo-EL-Graph RAG predictions")
    parser.add_argument("--predictions", required=True, type=Path)
    parser.add_argument("--golden", type=Path, default=GOLDEN_PATH)
    parser.add_argument("--k", type=int, default=5)
    args = parser.parse_args()
    print(json.dumps(evaluate(load_jsonl(args.golden), load_jsonl(args.predictions), args.k), indent=2))

if __name__ == "__main__": main()
