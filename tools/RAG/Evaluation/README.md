# RAG evaluation

## Metrics

- Retrieval: Precision@k, Recall@k, MRR and nDCG@k.
- Answer: exact match and token F1 (lexical baselines only).
- Grounding proxy: expected CVE citation coverage.
- Security: query rejection, injection detection, context boundary, PII redaction and output-size tests.
- Operational metrics to capture in orchestrator traces: end-to-end latency, retrieval latency, model latency, input/output tokens, retries, fallback rate, error rate and cost per query.

## Run tests

    python -m unittest discover -s tests -v

## Run evaluation

Prediction JSONL rows use this shape:

    {"id":"log4shell_lookup","retrieved_ids":["CVE-2021-44228"],"answer":"CVE-2021-44228 is Log4Shell, a critical remote code execution vulnerability in Apache Log4j."}

Run:

    python -m tools.RAG.Evaluation.evaluate --predictions path/to/predictions.jsonl --k 5

Verify each golden CVE is present in the actual filtered NVD dataset before using scores as release gates. Update the golden set with representative queries, hard negatives, no-answer cases and adversarial examples.

## Optional RAGAS

RAGAS is not a mandatory dependency. Once rows contain questions, retrieved contexts, answers and ground truth, add a compatible RAGAS environment for faithfulness, answer relevancy, context precision and context recall. Record dataset version, prompt version, model, embedding model, k, timestamp, latency and token usage for each run.

Exact match and token F1 are not semantic correctness measures. Review per-case failures and use human review for high-impact decisions.
