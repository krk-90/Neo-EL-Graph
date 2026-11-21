# MCP server and tools

## Start the server

From the repository root with the project virtual environment active:

```powershell
python -m tools.mcp_tools.server
```

The default Streamable HTTP endpoint is `http://127.0.0.1:8000/mcp`.
`config.yml` defines the default bind host, port, and network limits. Matching
environment variables in the shell or `.env` override those defaults.

To inspect the server, open a second terminal and run (Node.js/npm required):

```powershell
npx -y @modelcontextprotocol/inspector
```

Select **Streamable HTTP**, connect to the endpoint above, then open the
**Tools** tab. Keep the MCP server running while Inspector is connected.

## Tools

All tools that inspect a network target require an explicit `authorized_targets`
list. Use hostnames for DNS and exact authorized hostnames for hostname-based
checks; CIDRs authorize IP-based operations. These scopes are caller-supplied and
are not a substitute for backend authentication.

| Tool | Purpose |
|---|---|
| `network_discover_tool` | Check selected ports and reverse DNS within an authorized CIDR |
| `dns_lookup_tool` | Retrieve A, AAAA, MX, NS, and TXT records for an authorized hostname |
| `ping_host_tool` | Run one bounded ping check |
| `traceroute_host_tool` | Run a bounded route trace |
| `tcp_check_tool` | Check one authorized TCP port |
| `port_check_tool` | Check a bounded supplied port list |
| `tls_inspect_tool` | Inspect a TLS certificate and negotiated protocol |
| `network_diagnose_tool` | Run ping, route, and TCP diagnostics |
| `cve_lookup_tool` | Query the NVD API agent |
| `search_cve_knowledge_tool` | Search the existing Chroma/RAG index |
| `security_assessment_tool` | Run the LangGraph workflow and optional keyword correlation |

Handlers return an envelope containing `status`, `tool`, `duration_ms`, `output`,
and `error`. `status` is `success`, `partial`, or `error`; authorization,
invalid input, incomplete TLS checks, and unexpected execution failures are
distinguished. Detailed exception messages and credentials are not returned.
The security-assessment output also includes its execution trace and
partial-result status inside the handler envelope.

Operational limits are in `config.yml`; optional environment overrides are listed
in `.example.env`.
