# Testing and local smoke checks

Run the unit suite from the repository root:

```bash
python -m unittest discover -s tests -v
```

Run the configured Ruff checks after installing `requirements-dev.txt`:

```bash
ruff check .
```

The automated tests use mocked network operations and NVD responses. They do not
scan real hosts, make live NVD requests, or require a populated Chroma index.
They cover authorization, request routing, runtime configuration, MCP
registration, agent errors, RAG processing, guardrails, and evaluation metrics.

For an optional local MCP smoke check, start the server in one terminal:

```powershell
python -m tools.mcp_tools.server
```

Then connect MCP Inspector to `http://127.0.0.1:8000/mcp` from a second terminal.
Only invoke network tools against systems you own or are explicitly authorized
to test. A local TLS timeout is an inconclusive connectivity result, not a
certificate finding.

See [EVALUATION.md](EVALUATION.md) for the deterministic routing and
authorization dataset and [the RAG evaluation notes](tools/RAG/Evaluation/README.md)
for retrieval and generation metrics.
