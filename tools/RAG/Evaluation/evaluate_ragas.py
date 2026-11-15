"""Optional RAGAS semantic evaluation adapter.

Install a RAGAS release compatible with your LangChain/Python environment before use.
Prediction JSONL rows must include id, answer and contexts (a list of retrieved text).
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from tools.RAG.Evaluation.evaluate import GOLDEN_PATH, load_jsonl


def evaluate_ragas(golden: dict[str, dict], predictions: dict[str, dict]) -> dict:
    try:
        from datasets import Dataset
        from ragas import evaluate as ragas_evaluate
        from ragas.metrics import answer_relevancy, context_precision, context_recall, faithfulness
    except ImportError as exc:
        raise RuntimeError(
            "Optional RAGAS evaluation requires compatible 'ragas' and 'datasets' packages."
        ) from exc

    missing = sorted(set(golden) - set(predictions))
    if missing:
        raise ValueError("Missing predictions for: " + ", ".join(missing))

    rows = []
    for case_id, expected in golden.items():
        prediction = predictions[case_id]
        contexts = prediction.get("contexts")
        if not isinstance(contexts, list) or not all(isinstance(item, str) for item in contexts):
            raise ValueError(f"Prediction {case_id} must contain contexts as a list of strings.")
        rows.append({
            "question": expected["question"],
            "answer": prediction.get("answer", ""),
            "contexts": contexts,
            "ground_truth": expected.get("reference_answer", ""),
        })

    dataset = Dataset.from_list(rows)
    result = ragas_evaluate(
        dataset,
        metrics=[faithfulness, answer_relevancy, context_precision, context_recall],
    )
    frame = result.to_pandas()
    scores = {}
    for column in ("faithfulness", "answer_relevancy", "context_precision", "context_recall"):
        if column in frame:
            values = frame[column].dropna()
            scores[column] = float(values.mean()) if len(values) else 0.0
    return {"cases": len(rows), "ragas": scores}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run optional RAGAS semantic evaluation.")
    parser.add_argument("--predictions", required=True, type=Path)
    parser.add_argument("--golden", type=Path, default=GOLDEN_PATH)
    args = parser.parse_args()
    report = evaluate_ragas(load_jsonl(args.golden), load_jsonl(args.predictions))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
