# Neo-EL-Graph

Neo-EL-Graph is an experimental vulnerability-research RAG system. It processes National Vulnerability Database (NVD) CVE records, indexes them in Chroma with Hugging Face embeddings, retrieves evidence with hybrid vector + BM25 search and reranking, and can generate grounded answers with Groq. The repository also contains offline evaluation, security guardrail modules, and LangSmith tracing hooks.

> **Current scope:** the runnable workflow is the CVE data → Chroma → retrieval → optional answer-generation pipeline. The `agent/orchestrator/main.py` and `tools/mcp_tools/server.py` files are currently incomplete stubs; there is no ready-to-run API server or MCP server yet.

## Features

- NVD JSON normalization, filtering, and reproducible CVE sampling.
- Local Chroma persistence, with optional Chroma Cloud support.
- Hugging Face `all-MiniLM-L6-v2` embeddings (local or hosted endpoint).
- Hybrid semantic + BM25 retrieval and optional reranking.
- Optional Groq-powered, streaming RAG answers with CVE source metadata.
- Offline retrieval/generation metrics and optional RAGAS evaluation.
- Standalone RAG security guardrails and prompt templates.
- Optional LangSmith tracing.

## Requirements

- Python 3.10+ (use a version supported by the installed LangChain dependencies).
- Git.
- Internet access for installing packages and downloading the Hugging Face model.
- A Groq API key only if you want answer generation.
- Hugging Face token only if you choose hosted endpoint embeddings.
- Chroma Cloud credentials only if you choose Chroma Cloud instead of local Chroma.

## 1. Clone the repository

```bash
git clone https://github.com/krk-90/Neo-EL-Graph.git
cd Neo-EL-Graph
```

## 2. Create and activate a virtual environment

**Linux / macOS / Ubuntu**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

**Windows PowerShell**

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again.

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

The first local embedding/indexing run downloads the Hugging Face model and may also download PyTorch dependencies. This can take time and disk space.

## 4. Configure environment variables

**Linux / macOS / Ubuntu**

```bash
cp .example.env .env
```

**Windows PowerShell**

```powershell
Copy-Item .example.env .env
```

Open `.env` and configure only the services you use:

| Variable | Required? | Purpose |
|---|---|---|
| `HF_EMBEDDING_MODEL` | No | Defaults to `sentence-transformers/all-MiniLM-L6-v2`. |
| `HF_EMBEDDING_MODE` | No | `local` by default; use `endpoint` for hosted embeddings. |
| `HUGGINGFACEHUB_API_TOKEN` | Endpoint only | Token for hosted Hugging Face embeddings. |
| `GROQ_API_KEY` | Generation only | Enables the answer-generation command. |
| `CHROMA_API_KEY`, `CHROMA_TENANT`, `CHROMA_DATABASE` | Cloud only | Chroma Cloud credentials. |
| `CHROMA_COLLECTION` | No | Defaults to `cve_huggingface_minilm`. |
| `CHROMA_PERSIST_DIRECTORY` | No | Defaults to `Database/chroma_db` for local storage. |
| `LANGSMITH_API_KEY` | No | Enables LangSmith trace upload. |
| `LANGSMITH_TRACING`, `LANGSMITH_PROJECT` | No | Tracing configuration. |

**Important:** For local Chroma, leave `CHROMA_API_KEY` unset or remove the placeholder value from `.env`. If it is set, the ingestion code attempts to use Chroma Cloud and expects the tenant and database values too. Never commit your real `.env` file or API keys.

## 5. Prepare the NVD data (optional)

The repository already includes processed JSONL files under `Data/processed/`. If you want to rebuild them from a downloaded NVD JSON feed, place the source file in the repository and run:

```bash
python -m Data.data_analysis.normalize_nvd --input path/to/nvd.json --output Data/processed/nvd_normalized.jsonl
python Data/data_analysis/filter_nvd.py
```

The filter script reads `Data/processed/nvd_normalized.jsonl` and writes `Data/processed/nvd_filtered.jsonl`.

To inspect a feed or export a CSV:

```bash
python Data/data_analysis/data_load.py path/to/nvd.json --limit 10
python Data/data_analysis/data_load.py path/to/nvd.json --min-score 9.0 --limit 20
python Data/data_analysis/data_load.py path/to/nvd.json --search openssl --limit 20
python Data/data_analysis/data_load.py path/to/nvd.json --csv Data/processed/nvd_export.csv
```

To create a reproducible severity-balanced sample:

```bash
python -m Data.data_analysis.select_cves --input Data/processed/nvd_filtered.jsonl --output Data/processed/nvd_selected.jsonl --count 1000 --seed 42
```

To sample and ingest that selection directly into **local** Chroma:

```bash
python -m Data.data_analysis.select_cves --input Data/processed/nvd_filtered.jsonl --output Data/processed/nvd_selected.jsonl --count 1000 --seed 42 --ingest --batch-size 64
```

## 6. Build the Chroma index

From the repository root, run:

```bash
python -m tools.RAG.processing
```

This reads `Data/processed/nvd_filtered.jsonl`, chunks the CVE records, creates embeddings, and stores them in the configured Chroma collection. The default local collection directory is `Database/chroma_db`.

Useful options:

```bash
python -m tools.RAG.processing --help
python -m tools.RAG.processing --input Data/processed/nvd_selected.jsonl --collection cve_sample --batch-size 64
```

Use the same collection name and storage/cloud configuration when querying later.

## 7. Retrieve CVEs (without an LLM)

```bash
python -m tools.RAG.Retriever.retrieval --query "critical remote code execution vulnerabilities" --k 5
```

Return JSON:

```bash
python -m tools.RAG.Retriever.retrieval --query "Apache Log4j remote code execution" --k 5 --json
```

Disable reranking or refresh the in-memory BM25 index:

```bash
python -m tools.RAG.Retriever.retrieval --query "Linux kernel privilege escalation" --no-rerank
python -m tools.RAG.Retriever.retrieval --query "Apache Log4j" --refresh-bm25
```

Inspect indexed documents:

```bash
python -m tools.RAG.Retriever.retrieval --inspect --limit 10
```

The collection must be populated before retrieval. If it is empty, run the indexing step first.

## 8. Generate an answer with Groq (optional)

Set `GROQ_API_KEY` in `.env`, ensure the Chroma index exists, then run:

```bash
python -m tools.RAG.Generation.main "Find critical remote code execution vulnerabilities" --show-sources
```

More examples:

```bash
python -m tools.RAG.Generation.main "What is CVE-2021-44228 and what products are affected?"
python -m tools.RAG.Generation.main "Find high severity vulnerabilities related to OpenSSL" --show-sources
```

This command streams the answer and can print the retrieved CVE IDs, severity, CVSS score, and snippets. Groq is not needed for indexing or retrieval-only commands.

## 9. Run tests

Run the repository's unit tests from the project root:

```bash
python -m unittest discover -s tests -v
```

## 10. Run the offline RAG evaluation

The golden dataset is at `tools/RAG/Evaluation/golden_dataset.jsonl`. First create a predictions JSONL file with one row for every golden case. Each row must include the matching `id`, an ordered `retrieved_ids` list of CVE IDs, and the generated `answer`.

Example row format:

```json
{"id":"log4shell_lookup","retrieved_ids":["CVE-2021-44228"],"answer":"CVE-2021-44228 is Log4Shell, a critical remote code execution vulnerability in Apache Log4j."}
```

Then run:

```bash
python -m tools.RAG.Evaluation.evaluate --predictions path/to/predictions.jsonl --k 5
```

The evaluator reports Precision@k, Recall@k, MRR, nDCG@k, exact match, token F1, and expected-CVE citation coverage. Exact match and token F1 are lexical baselines, not proof of semantic correctness. Review individual failures; do not use a single aggregate score as the only release gate.

### Optional RAGAS evaluation

Install compatible `ragas` and `datasets` versions separately (they are not in the base requirements):

```bash
pip install ragas datasets
```

The predictions file must also include a `contexts` array of retrieved text for each case. Run:

```bash
python -m tools.RAG.Evaluation.evaluate_ragas --predictions path/to/predictions_with_contexts.jsonl
```

This reports faithfulness, answer relevancy, context precision, and context recall. RAGAS may require additional model/provider configuration depending on the installed version.

## 11. Security module

The security helpers and prompt templates are in `tools/RAG/Security/`. Read [the security integration notes](tools/RAG/Security/README.md) before wiring them into an application. They are not currently connected to the active retrieval/generation CLI pipeline, and pattern-based checks cannot guarantee prompt-injection immunity.

Run the security and RAG tests with the full test command in [Section 9](#9-run-tests).

## Project structure

```text
Neo-EL-Graph/
├── Data/
│   ├── data_analysis/       # NVD loading, normalization, filtering, sampling
│   └── processed/           # Processed CVE JSONL datasets
├── Database/                # Local Chroma persistence
├── agent/
│   ├── orchestrator/        # Incomplete orchestration entry point
│   └── rag_agent.py         # Agent wrapper requiring injected model/retriever
├── tools/
│   ├── RAG/
│   │   ├── Evaluation/      # Offline metrics and optional RAGAS adapter
│   │   ├── Generation/      # Groq answer generation
│   │   ├── Retriever/       # Hybrid retrieval and reranking
│   │   ├── Security/        # Guardrails and prompt templates
│   │   └── ingest/          # CVE loading, chunking, embeddings, Chroma
│   └── mcp_tools/           # Incomplete MCP server placeholder
├── tests/                   # Unit tests
├── .example.env             # Environment-variable template
└── requirements.txt
```

## Troubleshooting

- **Chroma collection is empty:** run `python -m tools.RAG.processing` and verify that the configured collection and local/cloud settings match between ingestion and retrieval.
- **Missing `GROQ_API_KEY`:** set it in `.env`; only the generation command needs it.
- **Local embedding runtime missing:** reinstall requirements inside the active virtual environment. The local mode uses `sentence-transformers`.
- **Hugging Face endpoint authentication error:** set `HF_EMBEDDING_MODE=endpoint` and `HUGGINGFACEHUB_API_TOKEN`.
- **Unexpected Chroma Cloud connection:** remove the placeholder `CHROMA_API_KEY` from `.env` to use local Chroma.
- **No LangSmith traces:** configure `LANGSMITH_API_KEY`; tracing is optional.
- **Import errors:** run commands from the repository root with the project virtual environment activated.

## License

No license file is currently included. Add a license before granting others permission to reuse, modify, or distribute this project.
