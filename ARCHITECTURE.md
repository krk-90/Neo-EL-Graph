# Architecture

## Runtime components

- `agent/nvd_api_agent.py` remains the single NVD 2.0 integration.
- `tools/RAG/` contains optional Chroma ingestion, hybrid retrieval, reranking,
  generation, evaluation, and guardrails.
- `agent/network/` contains authorization, discovery, DNS, TCP, TLS, and
  diagnostics agents.
- `agent/orchestrator/` classifies requests, validates targets, runs selected
  agents concurrently, correlates optional keywords, and returns partial results.
- `tools/mcp_tools/` exposes the same capabilities through the official MCP SDK.
- `agent/config.py` loads non-secret runtime defaults from `config.yml`; shell
  environment variables and `.env` values override those defaults.

Single-intent requests select a specialist. Multiple recognized intents select
multiple specialists; requests without a recognized intent select the default
assessment set. Supplying a target range adds discovery. DNS queries require an
exactly authorized hostname; CIDR authorization applies to IP-based operations.
Hostname-based TCP, TLS, and diagnostics connect to vetted resolved addresses
while preserving the hostname for TLS SNI and verification.

Failures are preserved in the execution trace and mark assessments as partial.
An open port is not evidence that a vulnerability affects the target. Optional
NVD/RAG correlation runs only when keywords are supplied.

## Trust boundary

The MCP server is a local development interface, not an authenticated backend.
It binds to loopback by default. `authorized_targets` is caller-supplied input,
not proof of authorization; a future network-facing backend must authenticate
callers and enforce server-side scopes before invoking these agents.
