# Security boundaries and deployment notes

This project is a pre-backend prototype. Its MCP HTTP endpoint is intended for
local development and binds to `127.0.0.1` by default. Do not expose it directly
to an untrusted network: it has no caller authentication or server-side identity
authorization.

Network tools require an explicit caller-supplied authorization scope. A future
backend must derive allowed scopes from authenticated identity and enforce them
server-side; a client-provided `authorized_targets` value is not proof of
permission.

The agents reject cloud metadata addresses, loopback/link-local, multicast,
unspecified addresses, oversized CIDRs, and targets outside the supplied scope.
Discovery, ports, concurrency, and timeouts are bounded by `config.yml`; shell
environment variables and `.env` may override those defaults.
Hostname-based TCP, TLS, and diagnostic connections resolve once, filter
prohibited addresses, and connect to the vetted IP rather than resolving again
at connection time.

No shell command accepts raw user input. Ping and traceroute use fixed executable
names and argument lists. DNS records and banners are treated as untrusted evidence.
API keys are never returned in MCP results.

Open ports are observations, not evidence that a vulnerability affects the target.
Network timeouts or failed TLS handshakes are incomplete checks, not vulnerability
findings. Confirmed product and version evidence is required before a CVE can be
described as affecting a target; keyword matches are only leads.
