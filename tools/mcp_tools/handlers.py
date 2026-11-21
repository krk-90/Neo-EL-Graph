"""Safe handlers that reuse existing agents and RAG services."""

from __future__ import annotations

import asyncio
import logging
import time
from functools import wraps
from typing import Callable

from pydantic import ValidationError

from agent.network.diagnostics_agent import NetworkDiagnosticsAgent
from agent.network.discovery_agent import NetworkDiscoveryAgent
from agent.network.dns_agent import DNSIntelligenceAgent
from agent.network.port_service_agent import PortServiceAnalysisAgent
from agent.network.security import network_limits
from agent.network.tls_agent import TLSSecurityAgent
from agent.nvd_api_agent import NVDApiAgent
from agent.orchestrator.graph import run_security_assessment
from tools.mcp_tools.schemas import (
    CVELookupInput,
    DiscoveryInput,
    DNSLookupInput,
    HostInput,
    NetworkDiagnoseInput,
    PortCheckInput,
    RAGSearchInput,
    SecurityAssessmentInput,
    TCPCheckInput,
    TLSInspectInput,
)

LOGGER = logging.getLogger(__name__)


def safe_handler(func: Callable[..., dict]) -> Callable[..., dict]:
    @wraps(func)
    def wrapper(*args, **kwargs) -> dict:
        started = time.monotonic()
        try:
            output = func(*args, **kwargs)
            status = "success"
            error = None
        except PermissionError:
            output = {}
            status = "error"
            error = {
                "category": "authorization_denied",
                "message": "Target is outside the authorized scope.",
            }
        except ValidationError:
            output = {}
            status = "error"
            error = {
                "category": "invalid_input",
                "message": "Input failed validation.",
            }
        except ValueError as exc:
            output = {}
            status = "error"
            error = {"category": "invalid_input", "message": str(exc)}
        except Exception as exc:
            output = {}
            status = "error"
            LOGGER.error(
                "MCP handler %s failed with %s.",
                func.__name__,
                type(exc).__name__,
            )
            error = {
                "category": "execution_failure",
                "message": "The operation could not be completed safely.",
                "error_type": type(exc).__name__,
            }
        if status == "success" and func.__name__ == "tls_inspect":
            tls_error = next(
                (
                    finding
                    for finding in output.get("findings", [])
                    if finding.get("category") == "tls_error"
                ),
                None,
            )
            if tls_error is not None:
                status = "error"
                error = {
                    "category": "execution_failure",
                    "message": "TLS inspection could not be completed.",
                    "error_type": tls_error.get(
                        "error_category", "TLSInspectionError"
                    ),
                }
        if (
            status == "success"
            and func.__name__ == "security_assessment"
            and output.get("assessment", {}).get("partial_results")
        ):
            status = "partial"
            error = {
                "category": "partial_result",
                "message": "One or more assessment agents did not complete.",
            }
        return {
            "status": status,
            "tool": func.__name__,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "output": output,
            "error": error,
        }

    return wrapper


@safe_handler
def network_discover(
    target_range: str, authorized_targets: list[str], ports: list[int] | None = None
) -> dict:
    request = DiscoveryInput(
        target_range=target_range,
        authorized_targets=authorized_targets,
        ports=ports or [],
    )
    limits = network_limits()
    return asyncio.run(
        NetworkDiscoveryAgent(
            max_concurrent=limits["max_concurrent"],
            timeout=limits["timeout"],
            max_hosts=limits["max_hosts"],
            max_ports=limits["max_ports"],
        ).discover(
            request.target_range,
            request.authorized_targets,
            request.ports or None,
        )
    )


@safe_handler
def dns_lookup(hostname: str, authorized_targets: list[str]) -> dict:
    request = DNSLookupInput(
        hostname=hostname,
        authorized_targets=authorized_targets,
    )
    return DNSIntelligenceAgent(timeout=network_limits()["timeout"]).lookup(
        request.hostname,
        request.authorized_targets,
    )


@safe_handler
def ping_host(host: str, authorized_targets: list[str]) -> dict:
    request = HostInput(host=host, authorized_targets=authorized_targets)
    return NetworkDiagnosticsAgent(timeout=network_limits()["timeout"]).ping(
        request.host,
        request.authorized_targets,
    )


@safe_handler
def traceroute_host(host: str, authorized_targets: list[str]) -> dict:
    request = HostInput(host=host, authorized_targets=authorized_targets)
    return NetworkDiagnosticsAgent(timeout=network_limits()["timeout"]).traceroute(
        request.host,
        request.authorized_targets,
    )


@safe_handler
def tcp_check(host: str, port: int, authorized_targets: list[str]) -> dict:
    request = TCPCheckInput(
        host=host,
        port=port,
        authorized_targets=authorized_targets,
    )
    limits = network_limits()
    return asyncio.run(
        PortServiceAnalysisAgent(
            timeout=limits["timeout"],
            max_concurrent=limits["max_concurrent"],
        ).check_ports(request.host, [request.port], request.authorized_targets)
    )


@safe_handler
def port_check(host: str, ports: list[int], authorized_targets: list[str]) -> dict:
    request = PortCheckInput(
        host=host,
        ports=ports,
        authorized_targets=authorized_targets,
    )
    limits = network_limits()
    return asyncio.run(
        PortServiceAnalysisAgent(
            timeout=limits["timeout"],
            max_concurrent=limits["max_concurrent"],
        ).check_ports(request.host, request.ports, request.authorized_targets)
    )


@safe_handler
def tls_inspect(host: str, port: int, authorized_targets: list[str]) -> dict:
    request = TLSInspectInput(
        host=host,
        port=port,
        authorized_targets=authorized_targets,
    )
    return TLSSecurityAgent(timeout=network_limits()["timeout"]).inspect(
        request.host,
        request.port,
        request.authorized_targets,
    )


@safe_handler
def network_diagnose(
    host: str, authorized_targets: list[str], include_traceroute: bool = True
) -> dict:
    request = NetworkDiagnoseInput(
        host=host,
        authorized_targets=authorized_targets,
        include_traceroute=include_traceroute,
    )
    limits = network_limits()
    agent = NetworkDiagnosticsAgent(timeout=limits["timeout"])
    ping = agent.ping(request.host, request.authorized_targets)
    route = (
        agent.traceroute(request.host, request.authorized_targets)
        if request.include_traceroute
        else None
    )
    ports = [80, 443][: limits["max_ports"]]
    tcp = asyncio.run(
        PortServiceAnalysisAgent(
            timeout=limits["timeout"],
            max_concurrent=limits["max_concurrent"],
        ).check_ports(request.host, ports, request.authorized_targets)
    )
    return {"ping": ping, "traceroute": route, "tcp": tcp}


@safe_handler
def cve_lookup(query: str, limit: int = 10, severity: str | None = None) -> dict:
    request = CVELookupInput(query=query, limit=limit, severity=severity)
    result = NVDApiAgent().ask(
        request.query,
        limit=request.limit,
        severity=request.severity,
    )
    return {
        "query": result.query,
        "cve_ids": list(result.cve_ids),
        "vulnerabilities": list(result.vulnerabilities),
    }


@safe_handler
def search_cve_knowledge(
    query: str, limit: int = 5, severity: str | None = None
) -> dict:
    request = RAGSearchInput(query=query, limit=limit, severity=severity)
    from tools.RAG.Retriever.retrieval import search_cves

    return {
        "results": search_cves.invoke(
            {
                "query": request.query,
                "limit": request.limit,
                "severity": request.severity,
            }
        )
    }


@safe_handler
def security_assessment(
    request: str,
    authorized_targets: list[str],
    target: str | None = None,
    target_range: str | None = None,
    ports: list[int] | None = None,
    keywords: list[str] | None = None,
) -> dict:
    request_input = SecurityAssessmentInput(
        request=request,
        authorized_targets=authorized_targets,
        target=target,
        target_range=target_range,
        ports=ports or [],
        keywords=keywords or [],
    )
    return run_security_assessment(
        request=request_input.request,
        target=request_input.target,
        target_range=request_input.target_range,
        authorized_targets=request_input.authorized_targets,
        ports=request_input.ports,
        keywords=request_input.keywords,
    )
