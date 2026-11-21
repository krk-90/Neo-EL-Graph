"""Dependency-light retrieval and answer evaluation metrics."""

from __future__ import annotations

import math
import re
from collections.abc import Sequence


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.casefold()).strip()


def precision_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    if k <= 0:
        raise ValueError("k must be greater than zero")
    return sum(item in relevant for item in retrieved[:k]) / k


def recall_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    if k <= 0:
        raise ValueError("k must be greater than zero")
    return len(set(retrieved[:k]) & relevant) / len(relevant) if relevant else 0.0


def reciprocal_rank(retrieved: Sequence[str], relevant: set[str]) -> float:
    for rank, item in enumerate(retrieved, start=1):
        if item in relevant:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    if k <= 0:
        raise ValueError("k must be greater than zero")
    dcg = sum(
        1.0 / math.log2(rank + 1)
        for rank, item in enumerate(retrieved[:k], start=1)
        if item in relevant
    )
    ideal = min(len(relevant), k)
    idcg = sum(1.0 / math.log2(rank + 1) for rank in range(1, ideal + 1))
    return dcg / idcg if idcg else 0.0


def exact_match(prediction: str, reference: str) -> float:
    return float(_normalize(prediction) == _normalize(reference))


def token_f1(prediction: str, reference: str) -> float:
    pred, ref = _normalize(prediction).split(), _normalize(reference).split()
    if not pred or not ref:
        return float(pred == ref)
    common = sum(min(pred.count(token), ref.count(token)) for token in set(pred))
    if not common:
        return 0.0
    precision, recall = common / len(pred), common / len(ref)
    return 2 * precision * recall / (precision + recall)


def citation_coverage(answer: str, expected_ids: set[str]) -> float:
    if not expected_ids:
        return 1.0
    found = {item for item in expected_ids if item.casefold() in answer.casefold()}
    return len(found) / len(expected_ids)


def aggregate(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        return 0.0
    if not 0 <= percentile <= 100:
        raise ValueError("percentile must be between 0 and 100")
    ordered = sorted(float(value) for value in values)
    index = max(0, math.ceil((percentile / 100) * len(ordered)) - 1)
    return ordered[index]


def summarize_runtime(records: Sequence[dict]) -> dict:
    """Summarize optional per-request operational measurements.

    Expected keys: latency_ms, retries, fallback, error, input_tokens,
    output_tokens and cost_usd. Missing numeric values are treated as zero.
    """
    if not records:
        return {
            "requests": 0,
            "latency_ms_p50": 0.0,
            "latency_ms_p95": 0.0,
            "retry_rate": 0.0,
            "fallback_rate": 0.0,
            "error_rate": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
        }
    count = len(records)
    latencies = [max(0.0, float(row.get("latency_ms", 0) or 0)) for row in records]
    return {
        "requests": count,
        "latency_ms_p50": _percentile(latencies, 50),
        "latency_ms_p95": _percentile(latencies, 95),
        "retry_rate": sum(bool(row.get("retries", 0)) for row in records) / count,
        "fallback_rate": sum(bool(row.get("fallback", False)) for row in records)
        / count,
        "error_rate": sum(bool(row.get("error", False)) for row in records) / count,
        "input_tokens": sum(int(row.get("input_tokens", 0) or 0) for row in records),
        "output_tokens": sum(int(row.get("output_tokens", 0) or 0) for row in records),
        "cost_usd": sum(float(row.get("cost_usd", 0) or 0) for row in records),
    }
