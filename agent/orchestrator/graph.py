"""LangGraph workflow for coordinated network and vulnerability intelligence."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from agent.orchestrator.nodes import (
    assess_node,
    classify_node,
    correlate_node,
    execute_node,
    validate_node,
)


def build_network_graph():
    graph = StateGraph(dict)
    graph.add_node("classify", classify_node)
    graph.add_node("validate", validate_node)
    graph.add_node("execute", execute_node)
    graph.add_node("correlate", correlate_node)
    graph.add_node("assess", assess_node)

    graph.set_entry_point("classify")
    graph.add_edge("classify", "validate")
    graph.add_edge("validate", "execute")
    graph.add_edge("execute", "correlate")
    graph.add_edge("correlate", "assess")
    graph.add_edge("assess", END)
    return graph.compile()


def run_security_assessment(
    request: str,
    target: str | None = None,
    target_range: str | None = None,
    authorized_targets: list[str] | None = None,
    ports: list[int] | None = None,
    keywords: list[str] | None = None,
) -> dict:
    if not authorized_targets:
        raise ValueError("authorized_targets is required.")
    initial = {
        "request": request,
        "target": target,
        "target_range": target_range,
        "authorized_targets": authorized_targets,
        "ports": ports or [],
        "keywords": keywords or [],
        "execution_trace": [],
    }
    return build_network_graph().invoke(initial)
