"""LangGraph nodes for defensive network intelligence workflows."""

from __future__ import annotations

import asyncio
import re
import time
import uuid

from agent.network.diagnostics_agent import NetworkDiagnosticsAgent
from agent.network.discovery_agent import NetworkDiscoveryAgent
from agent.network.dns_agent import DNSIntelligenceAgent
from agent.network.port_service_agent import PortServiceAnalysisAgent
from agent.network.security import (
    AuthorizationScope,
    network_limits,
    target_is_authorized,
    utc_now,
    validate_hostname,
    validate_ip_or_cidr,
)
from agent.network.tls_agent import TLSSecurityAgent
from agent.nvd_api_agent import NVDApiAgent


def classify_node(state: dict) -> dict:
    text = str(state.get("request", "")).lower()
    intents = (
        ("dns", r"\bdns\b", "dns_intelligence"),
        ("ports", r"\bports?\b|\bservices?\b", "port_service_analysis"),
        ("tls", r"\btls\b|\bcertificates?\b", "tls_security"),
        (
            "diagnostics",
            r"\broute\b|\brouting\b|\btraceroute\b|\bping\b",
            "network_diagnostics",
        ),
        (
            "discovery",
            r"\bdiscover(?:y)?\b|\bscan(?:ning)?\b",
            "network_discovery",
        ),
    )
    matches = [
        (classification, agent)
        for classification, pattern, agent in intents
        if re.search(pattern, text)
    ]
    target_range = state.get("target_range")
    target = state.get("target")
    if matches and target_range and all(
        agent != "network_discovery" for _, agent in matches
    ):
        matches.append(("discovery", "network_discovery"))

    if not state.get("selected_agents"):
        if matches:
            state["selected_agents"] = [agent for _, agent in matches]
        elif target_range and not target:
            state["selected_agents"] = ["network_discovery"]
        else:
            state["selected_agents"] = [
                "network_diagnostics",
                "dns_intelligence",
                "port_service_analysis",
                "tls_security",
            ]
            if target_range:
                state["selected_agents"].append("network_discovery")

    if len(matches) > 1:
        classification = "combined"
    elif matches:
        classification = matches[0][0]
    elif target_range and not target:
        classification = "discovery"
    else:
        classification = "assessment"
    state["classification"] = classification
    state["request_id"] = state.get("request_id") or str(uuid.uuid4())
    return state


def validate_node(state: dict) -> dict:
    authorized = state.get("authorized_targets")
    scope = AuthorizationScope.from_values(authorized)
    target = state.get("target") or ""
    target_range = state.get("target_range")
    trace = list(state.get("execution_trace", []))
    trace.append(
        {
            "node": "validate",
            "agent": "authorization",
            "success": True,
            "timestamp": utc_now(),
        }
    )
    if target_range:
        normalized_range = validate_ip_or_cidr(target_range)
        state["target_range"] = normalized_range
        network_ok = normalized_range in scope.allowed_targets or target_is_authorized(
            normalized_range, scope
        )
        if not network_ok:
            raise PermissionError("Target range is outside the authorized scope.")
    if target:
        if "/" in target:
            raise ValueError(
                "Target must be a single host; use target_range for CIDRs."
            )
        try:
            validate_ip_or_cidr(target)
        except ValueError:
            target = validate_hostname(target)
        if not target_is_authorized(target, scope):
            raise PermissionError("Target is outside the authorized scope.")
        state["target"] = target
    if not target and not target_range:
        raise ValueError("A target or target_range is required.")
    if (
        "network_discovery" in state.get("selected_agents", [])
        and not state.get("target_range")
    ):
        raise ValueError("A target_range is required for network discovery.")
    if not target and target_range and any(
        agent != "network_discovery"
        for agent in state.get("selected_agents", [])
    ):
        raise ValueError("A target is required for the selected network agents.")
    state["execution_trace"] = trace
    return state


async def execute_node_async(state: dict) -> dict:
    trace = list(state.get("execution_trace", []))
    results: dict = {}
    tasks = []
    names = state.get("selected_agents", [])
    target = state.get("target")
    authorized = state["authorized_targets"]
    ports = state.get("ports") or [443, 80]
    limits = network_limits()

    async def run(name: str, coroutine):
        started = time.monotonic()
        retry_count = 0
        try:
            output = await coroutine
            status = "success"
        except Exception as exc:
            output = {"error_category": type(exc).__name__}
            status = "failure"
            error_category = type(exc).__name__
        else:
            if name == "tls_security" and any(
                finding.get("category") == "tls_error"
                for finding in output.get("findings", [])
            ):
                status = "failure"
                error_category = next(
                    (
                        finding.get("error_category", "TLSInspectionError")
                        for finding in output.get("findings", [])
                        if finding.get("category") == "tls_error"
                    ),
                    "TLSInspectionError",
                )
            else:
                error_category = None
        trace.append(
            {
                "request_id": state["request_id"],
                "agent": name,
                "status": status,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
                "retry_count": retry_count,
                **(
                    {"error_category": error_category}
                    if error_category is not None
                    else {}
                ),
                "timestamp": utc_now(),
            }
        )
        results[name] = output

    if "network_discovery" in names:
        tasks.append(
            run(
                "network_discovery",
                NetworkDiscoveryAgent(
                    max_concurrent=limits["max_concurrent"],
                    timeout=limits["timeout"],
                    max_hosts=limits["max_hosts"],
                    max_ports=limits["max_ports"],
                ).discover(
                    state["target_range"], authorized, ports or None
                ),
            )
        )
    if "dns_intelligence" in names and target:
        tasks.append(
            run(
                "dns_intelligence",
                asyncio.to_thread(
                    DNSIntelligenceAgent(timeout=limits["timeout"]).lookup,
                    target,
                    authorized,
                ),
            )
        )
    if "port_service_analysis" in names and target:
        tasks.append(
            run(
                "port_service_analysis",
                PortServiceAnalysisAgent(
                    timeout=limits["timeout"],
                    max_concurrent=limits["max_concurrent"],
                ).check_ports(target, ports, authorized),
            )
        )
    if "network_diagnostics" in names and target:
        diagnostics = NetworkDiagnosticsAgent(timeout=limits["timeout"])
        tasks.append(
            run(
                "network_diagnostics",
                asyncio.to_thread(
                    lambda: {
                        "agent": "network_diagnostics",
                        "ping": diagnostics.ping(target, authorized),
                        "traceroute": diagnostics.traceroute(target, authorized),
                        "timestamp": utc_now(),
                    }
                ),
            )
        )
    if "tls_security" in names and target:
        tls_port = 443 if 443 in ports else ports[0]
        tasks.append(
            run(
                "tls_security",
                asyncio.to_thread(
                    TLSSecurityAgent(timeout=limits["timeout"]).inspect,
                    target,
                    tls_port,
                    authorized,
                ),
            )
        )

    await asyncio.gather(*tasks)
    state["results"] = results
    state["execution_trace"] = trace
    return state


def execute_node(state: dict) -> dict:
    return asyncio.run(execute_node_async(state))


def correlate_node(state: dict) -> dict:
    nvd = NVDApiAgent()
    nvd_results = []
    rag_results = []
    findings = []
    evidence = state.get("keywords") or []

    tls_result = state.get("results", {}).get("tls_security", {})
    for finding in tls_result.get("findings", []):
        if finding.get("category") == "tls_error":
            continue
        findings.append(
            {
                "finding_id": f"TLS-{len(findings) + 1}",
                "target": tls_result.get("host"),
                "observation": finding["observation"],
                "evidence_source": "tls_security",
                "related_cve_ids": [],
                "cvss_score": None,
                "severity": "MEDIUM",
                "confidence": "high",
                "recommended_remediation": (
                    "Update certificate/protocol configuration and revalidate."
                ),
                "timestamp": utc_now(),
            }
        )

    if evidence:
        query = " ".join(dict.fromkeys(evidence))[:200]
        try:
            nvd_results = nvd.search(query, limit=5)
        except Exception as exc:
            nvd_results = []
            state["execution_trace"].append(
                {
                    "agent": "nvd_correlation",
                    "status": "failure",
                    "error_category": type(exc).__name__,
                    "timestamp": utc_now(),
                }
            )

        try:
            from tools.RAG.Retriever.retrieval import search_cves

            rag_results = search_cves.invoke({"query": query, "limit": 5})
        except Exception as exc:
            rag_results = []
            state["execution_trace"].append(
                {
                    "agent": "rag_correlation",
                    "status": "failure",
                    "error_category": type(exc).__name__,
                    "timestamp": utc_now(),
                }
            )

    state["nvd_results"] = nvd_results
    state["rag_results"] = rag_results
    state["findings"] = findings
    state["execution_trace"] = list(state.get("execution_trace", [])) + [
        {
            "node": "correlate",
            "nvd_result_count": len(nvd_results),
            "rag_result_count": len(rag_results),
            "timestamp": utc_now(),
        }
    ]
    return state


def assess_node(state: dict) -> dict:
    failures = [
        item
        for item in state.get("execution_trace", [])
        if item.get("status") == "failure"
    ]
    findings = list(state.get("findings", []))
    if state.get("nvd_results"):
        for vuln in state["nvd_results"][:5]:
            findings.append(
                {
                    "finding_id": f"CVE-{len(findings) + 1}",
                    "target": state.get("target"),
                    "observation": vuln.get("description", ""),
                    "evidence_source": "NVD keyword search",
                    "related_cve_ids": [vuln.get("cve_id")],
                    "cvss_score": vuln.get("cvss", {}).get("score"),
                    "severity": vuln.get("cvss", {}).get("severity", "UNKNOWN"),
                    "confidence": "possible",
                    "recommended_remediation": (
                        "Confirm product and version evidence before remediation."
                    ),
                    "timestamp": utc_now(),
                }
            )
    summary = (
        f"Security assessment for {state.get('target') or state.get('target_range')}: "
        f"{len(findings)} evidence-based finding(s); "
        f"{len(failures)} specialist execution failure(s). "
        "Open ports and CVE search results are not confirmed exploitation matches."
    )
    state["assessment"] = {
        "request_id": state["request_id"],
        "classification": state["classification"],
        "summary": summary,
        "findings": findings,
        "partial_results": bool(failures),
        "timestamp": utc_now(),
    }
    return state
