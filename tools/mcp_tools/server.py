"""Neo-EL-Graph MCP server for defensive network and CVE intelligence."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from agent.config import load_runtime_config
from tools.mcp_tools.handlers import (
    cve_lookup,
    dns_lookup,
    network_diagnose,
    network_discover,
    ping_host,
    port_check,
    search_cve_knowledge,
    security_assessment,
    tcp_check,
    tls_inspect,
    traceroute_host,
)

CONFIG = load_runtime_config()
mcp = FastMCP(
    "neo-el-network-intelligence",
    host=CONFIG.mcp_host,
    port=CONFIG.mcp_port,
)


@mcp.tool(description="Discover hosts within an explicitly authorized CIDR range.")
def network_discover_tool(
    target_range: str,
    authorized_targets: list[str],
    ports: list[int] | None = None,
) -> dict:
    return network_discover(target_range, authorized_targets, ports)


@mcp.tool(
    description=(
        "Retrieve A, AAAA, MX, NS, and TXT DNS records for an authorized hostname."
    )
)
def dns_lookup_tool(hostname: str, authorized_targets: list[str]) -> dict:
    return dns_lookup(hostname, authorized_targets)


@mcp.tool(description="Run a single safe ping check for an authorized host.")
def ping_host_tool(host: str, authorized_targets: list[str]) -> dict:
    return ping_host(host, authorized_targets)


@mcp.tool(description="Run a limited traceroute for an authorized host.")
def traceroute_host_tool(host: str, authorized_targets: list[str]) -> dict:
    return traceroute_host(host, authorized_targets)


@mcp.tool(description="Check one TCP port on an explicitly authorized host.")
def tcp_check_tool(host: str, port: int, authorized_targets: list[str]) -> dict:
    return tcp_check(host, port, authorized_targets)


@mcp.tool(description="Check a user-supplied list of ports on an authorized host.")
def port_check_tool(host: str, ports: list[int], authorized_targets: list[str]) -> dict:
    return port_check(host, ports, authorized_targets)


@mcp.tool(description="Inspect a TLS certificate and basic protocol configuration.")
def tls_inspect_tool(host: str, port: int, authorized_targets: list[str]) -> dict:
    return tls_inspect(host, port, authorized_targets)


@mcp.tool(
    description="Run combined ping, route, and TCP diagnostics for an authorized host."
)
def network_diagnose_tool(
    host: str,
    authorized_targets: list[str],
    include_traceroute: bool = True,
) -> dict:
    return network_diagnose(host, authorized_targets, include_traceroute)


@mcp.tool(description="Look up CVE information from the existing NVD API agent.")
def cve_lookup_tool(query: str, limit: int = 10, severity: str | None = None) -> dict:
    return cve_lookup(query, limit, severity)


@mcp.tool(description="Search the existing Chroma and RAG CVE knowledge base.")
def search_cve_knowledge_tool(
    query: str, limit: int = 5, severity: str | None = None
) -> dict:
    return search_cve_knowledge(query, limit, severity)


@mcp.tool(
    description="Run the coordinated LangGraph network security assessment workflow."
)
def security_assessment_tool(
    request: str,
    authorized_targets: list[str],
    target: str | None = None,
    target_range: str | None = None,
    ports: list[int] | None = None,
    keywords: list[str] | None = None,
) -> dict:
    return security_assessment(
        request,
        authorized_targets,
        target,
        target_range,
        ports,
        keywords,
    )


def main() -> None:
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
