 # Neo-EL-Graph Brain Architecture

## Design goal

Build a persistent cybersecurity intelligence system whose advantage comes from evidence-backed knowledge, graph discovery, repeatable investigations, and measured improvement—not from multiplying chat agents.

## Layers

1. **Signal ingestion** — import public advisories, dependency manifests, repository metadata, logs, and analyst-provided intelligence.
2. **Normalization and provenance** — convert source material into typed entities and relationships. Preserve source URLs, observation time, confidence, and verification state.
3. **Persistent knowledge graph** — store repositories, packages, vulnerabilities, techniques, indicators, evidence, findings, and typed relationships. SQLite is the initial local adapter; Neo4j is the planned graph-scale adapter.
4. **Retrieval and reasoning** — match query terms to known entities and traverse a bounded neighborhood. Future reasoning providers may propose hypotheses, but should not directly assert unverified facts.
5. **Verification and safety** — distinguish verified evidence from hypotheses, surface evidence gaps, and require explicit approval for any active or destructive security action.
6. **Outcome learning** — store investigator feedback and evaluation results. Analyze error categories and test proposed changes against a fixed benchmark before promotion.
7. **Observability and interface** — FastAPI endpoints, dashboard, audit history, latency and quality metrics.

## Data model

- `Repository`, `Package`, `Vulnerability`, `ThreatActor`, `Technique`, `Indicator`, `Evidence`, `Finding`
- Relationships such as `DEPENDS_ON`, `AFFECTED_BY`, `USES_TECHNIQUE`, `OBSERVED_INDICATOR`, and `SUPPORTED_BY`
- Every claim should retain provenance. Confidence is not a substitute for evidence.

## Learning policy

The prototype records feedback but does **not** automatically fine-tune a model, mutate its own source code, or promote new graph claims to verified status. A future learning pipeline should:

1. Capture labeled investigation outcomes.
2. Categorize errors (missed retrieval, incorrect relationship, unsupported claim, stale source, bad prioritization).
3. Generate a candidate change to retrieval, graph traversal, or reasoning policy.
4. Run a versioned benchmark and regression tests.
5. Promote only if quality improves without unacceptable safety regressions.

## Initial API

- `GET /health`
- `GET /api/brain/overview`
- `GET /api/graph`
- `POST /api/knowledge/ingest`
- `POST /api/investigate`
- `POST /api/feedback`
- `POST /api/demo/seed` (synthetic, unverified demo data only)

## Local run

    python -m venv .venv
    # Windows: .venv\\Scripts\\activate
    # macOS/Linux: source .venv/bin/activate
    pip install -r requirements.txt
    uvicorn app.main:app --reload

Open http://127.0.0.1:8000 for the visual dashboard and /docs for interactive API documentation.

## Important limitation

This is a functional starter, not a validated autonomous cyber analyst. It currently uses a persistent SQLite graph representation and keyword-based graph retrieval. It does not yet connect live feeds, Neo4j, an LLM, a vector index, or external security tools. The UI demo fixture is synthetic and must never be treated as real threat intelligence.
