# Neo-EL-Graph

Neo-EL-Graph is a pre-backend prototype for vulnerability intelligence. It
includes a direct NVD API agent, authorized network-analysis agents, a local
Streamable HTTP MCP server, and separate experimental Chroma/RAG tools.

> **Scope:** this repository does not yet provide an authenticated production
> backend. The MCP server binds to loopback by default. Network tools require
> caller-supplied authorization scopes; a future backend must enforce those
> scopes using trusted identity rather than trusting client input.

## Run a network assessment

Activate the virtual environment and run commands from the repository root.
Requests are simple keyword-routed phrases. Multiple recognized intents can run
together; an unrecognized request selects the full assessment workflow.

Check TLS on one explicitly authorized host:

```powershell
python -m agent.orchestrator.main "Check TLS certificate" --target 192.168.1.10 --authorized-target 192.168.1.0/24 --port 443
```

Run DNS and TLS together on a hostname that you are authorized to assess:

```powershell
python -m agent.orchestrator.main "Check DNS and TLS" --target server.example.com --authorized-target server.example.com --port 443
```

DNS lookups require an explicitly authorized hostname. An IP address with a
CIDR scope is valid for IP-based checks such as TCP and TLS, but not for DNS
record lookup. Use a target and scope that you control; replace example values
with your own authorized systems.

Discover hosts in an authorized range:

```powershell
python -m agent.orchestrator.main "Discover hosts" --target-range 192.168.1.0/24 --authorized-target 192.168.1.0/24 --port 80 --port 443
```

Use `--keyword` to request NVD and optional RAG correlation during a network
assessment. NVD correlation makes a live API request; RAG correlation requires
a populated local or cloud Chroma collection. Unavailable correlation services
are reported as partial results rather than silently treated as empty matches:

```powershell
python -m agent.orchestrator.main "Assess this authorized host" --target server.example.com --authorized-target server.example.com --keyword nginx --port 443
```

## Run the MCP server

Start the local Streamable HTTP server:

```powershell
python -m tools.mcp_tools.server
```

The default endpoint is `http://127.0.0.1:8000/mcp`. To inspect it, run in a
second terminal (Node.js/npm required):

```powershell
npx -y @modelcontextprotocol/inspector
```

In Inspector, select **Streamable HTTP**, connect to the endpoint, and open the
**Tools** tab. Keep the server running while Inspector is connected. See
[MCP_TOOLS.md](MCP_TOOLS.md) for the available tools and inputs.

## Features

- NVD JSON normalization, filtering, and reproducible CVE sampling.
- Local Chroma persistence, with optional Chroma Cloud support.
- Hugging Face `all-MiniLM-L6-v2` embeddings (local or hosted endpoint).
- Hybrid semantic + BM25 retrieval and optional reranking.
- Optional Groq-powered, streaming RAG answers with CVE source metadata.
- Offline retrieval/generation metrics and optional RAGAS evaluation.
- Standalone RAG security guardrails and prompt templates.
- Optional LangSmith tracing.
- Authorized DNS, TCP, TLS, discovery, ping, and traceroute tools.
- LangGraph orchestration and a local MCP server for network and CVE tools.

## Requirements

- Python 3.10+ (use a version supported by the installed LangChain dependencies).
- Git.
- Internet access for installing packages and downloading the Hugging Face model.
- Node.js/npm only if you want to run MCP Inspector.
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
python -m pip install -r requirements.txt
```

For the configured Ruff import checks, install the development dependencies:

```bash
python -m pip install -r requirements-dev.txt
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

Runtime defaults for MCP and network limits are in [`config.yml`](config.yml).
Environment variables from the shell or `.env` override those values. The
precedence is shell environment, `.env`, `config.yml`, then built-in defaults.
Keep credentials in `.env`; do not put secrets in `config.yml`.

Open `.env` and configure only the services you use:

| Variable | Required? | Purpose |
|---|---|---|
| `HF_EMBEDDING_MODEL` | No | Defaults to `sentence-transformers/all-MiniLM-L6-v2`. |
| `HF_EMBEDDING_MODE` | No | `local` by default; use `endpoint` for hosted embeddings. |
| `HUGGINGFACEHUB_API_TOKEN` or `HF_TOKEN` | Endpoint only | Token for hosted Hugging Face embeddings. |
| `GROQ_API_KEY` | Generation only | Enables the answer-generation command. |
| `NVD_API_KEY` | No | Optional key for higher NVD API rate limits. |
| `CHROMA_API_KEY`, `CHROMA_TENANT`, `CHROMA_DATABASE` | Chroma Cloud only | Cloud credentials; leave blank for local Chroma. |
| `CHROMA_COLLECTION` | No | Defaults to `cve_huggingface_minilm`. |
| `CHROMA_PERSIST_DIRECTORY` | No | Defaults to `Database/chroma_db` for local storage. |
| `LANGSMITH_API_KEY` | No | Enables LangSmith tracing when configured. |
| `LANGSMITH_TRACING`, `LANGSMITH_PROJECT` | No | Tracing options; tracing is disabled by default. |
| `MCP_HOST`, `MCP_PORT` | No | Optional overrides for MCP bind host and port; port must be 1–65535. |
| `NETWORK_MAX_HOSTS` | No | Discovery cap; 1–256 hosts. |
| `NETWORK_MAX_PORTS` | No | Maximum distinct ports per operation; 1–64. |
| `NETWORK_MAX_CONCURRENT` | No | Concurrent network tasks; 1–256. |
| `NETWORK_REQUEST_TIMEOUT_SECONDS` | No | Network timeout; 1–300 seconds. |

Never commit `.env` or API keys. For local Chroma, leave the three cloud
credentials blank; any non-empty `CHROMA_API_KEY` enables the cloud path.

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

## 8. Query the NVD API agent

In direct NVD-query mode, the CLI calls the NVD 2.0 API and does not use Chroma
or RAG retrieval.

```powershell
python -m agent.orchestrator.main CVE-2021-44228
python -m agent.orchestrator.main "remote code execution" --severity CRITICAL --limit 10
```

Set `NVD_API_KEY` in `.env` to increase NVD API rate limits.

Fetch and merge CVE records into a JSONL dataset without invoking RAG:

```powershell
python -m Data.data_analysis.fetch_nvd_api CVE-2021-44228 CVE-2021-45046 --output Data/processed/nvd_filtered.jsonl
```

## 9. Generate an answer with Groq (optional)

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

## 10. Run tests

Run the repository's unit tests from the project root:

```bash
python -m unittest discover -s tests -v
```

The deterministic network routing/authorization evaluation is separate from the
unit suite:

```bash
python -m tools.network_evaluation
```

It reads `Data/network_golden.jsonl` and refreshes `Data/network_evaluation.json`
and `EVALUATION.md`; it does not contact real hosts.

## 11. Run the offline RAG evaluation

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

## 12. Security module

The security helpers and prompt templates are in `tools/RAG/Security/`. Read [the security integration notes](tools/RAG/Security/README.md) before wiring them into an application. They are not currently connected to the active retrieval/generation CLI pipeline, and pattern-based checks cannot guarantee prompt-injection immunity.

Run the security and RAG tests with the full test command in
[Section 10](#10-run-tests).

## Project structure

```text
Neo-EL-Graph/
├── Data/
│   ├── data_analysis/       # NVD loading, normalization, filtering, sampling
│   └── processed/           # Processed CVE JSONL datasets
├── Database/                # Local Chroma persistence
├── agent/
│   ├── network/             # Authorized network-analysis agents
│   ├── orchestrator/        # LangGraph workflow and CLI
│   ├── config.py            # YAML defaults and environment overrides
│   └── nvd_api_agent.py     # Exact-CVE and keyword NVD API agent
├── tools/
│   ├── RAG/
│   │   ├── Evaluation/      # Offline metrics and optional RAGAS adapter
│   │   ├── Generation/      # Groq answer generation
│   │   ├── Retriever/       # Hybrid retrieval and reranking
│   │   ├── Security/        # Guardrails and prompt templates
│   │   └── ingest/          # CVE loading, chunking, embeddings, Chroma
│   └── mcp_tools/           # Streamable HTTP MCP server and tool handlers
├── tests/                   # Unit tests
├── config.yml               # Non-secret MCP and network defaults
├── .example.env             # Environment-variable template
├── requirements.txt         # Runtime dependencies
└── requirements-dev.txt     # Runtime dependencies plus Ruff
```

## Troubleshooting

- **Chroma collection is empty:** run `python -m tools.RAG.processing` and verify that the configured collection and local/cloud settings match between ingestion and retrieval.
- **Missing `GROQ_API_KEY`:** set it in `.env`; only the generation command needs it.
- **Local embedding runtime missing:** reinstall requirements inside the active virtual environment. The local mode uses `sentence-transformers`.
- **Hugging Face endpoint authentication error:** set `HF_EMBEDDING_MODE=endpoint` and `HUGGINGFACEHUB_API_TOKEN`.
- **Unexpected Chroma Cloud connection:** remove the placeholder `CHROMA_API_KEY` from `.env` to use local Chroma.
- **No LangSmith traces:** configure `LANGSMITH_API_KEY`; tracing is optional.
- **FastMCP import error mentioning MCP 2.x:** activate the project virtual environment and run `python -m pip install -r requirements.txt`; this project uses the MCP v1 API.
- **Invalid runtime configuration:** check `config.yml` and the optional `MCP_*` / `NETWORK_*` overrides in `.env`; numeric values must be within the documented bounds.
- **TLS timeout:** the host or port may be unreachable, filtered, or not serving TLS. This is an incomplete check, not a certificate vulnerability.
- **Import errors:** run commands from the repository root with the project virtual environment activated.

## License

No license file is currently included. Add a license before granting others permission to reuse, modify, or distribute this project.
