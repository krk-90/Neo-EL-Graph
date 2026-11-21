"""Typed state for the network intelligence LangGraph workflow."""

from __future__ import annotations

from typing import Any, TypedDict


class OrchestratorState(TypedDict, total=False):
    request_id: str
    request: str
    target: str
    target_range: str | None
    authorized_targets: list[str]
    ports: list[int]
    keywords: list[str]
    classification: str
    selected_agents: list[str]
    results: dict[str, Any]
    execution_trace: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    rag_results: list[dict[str, Any]]
    nvd_results: list[dict[str, Any]]
    assessment: dict[str, Any]
