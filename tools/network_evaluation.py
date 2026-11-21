"""Small deterministic evaluation suite for network routing and authorization."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.network.security import (  # noqa: E402
    AuthorizationScope,
    target_is_authorized,
)
from agent.orchestrator.nodes import classify_node  # noqa: E402


def evaluate(golden_path: Path) -> dict:
    cases = [
        json.loads(line)
        for line in golden_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    route_correct = 0
    authorization_correct = 0
    for case in cases:
        state = classify_node({"request": case["request"]})
        if state["classification"] == case["expected_classification"]:
            route_correct += 1
        scope = AuthorizationScope.from_values(case["authorized_targets"])
        actual_authorized = target_is_authorized(case["target"], scope)
        if actual_authorized == case["expected_authorized"]:
            authorization_correct += 1
    return {
        "case_count": len(cases),
        "routing_accuracy": route_correct / len(cases) if cases else 0.0,
        "authorization_accuracy": authorization_correct / len(cases) if cases else 0.0,
        "measured": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="Data/network_golden.jsonl")
    parser.add_argument("--json-output", default="Data/network_evaluation.json")
    parser.add_argument("--markdown-output", default="EVALUATION.md")
    args = parser.parse_args()
    report = evaluate(Path(args.input))
    Path(args.json_output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown = (
        "# Network Agent Evaluation\n\n"
        "Deterministic checks of request routing and authorization against "
        "`Data/network_golden.jsonl`. These metrics do not measure live host "
        "reachability or the quality of network findings.\n\n"
        "Regenerate this report with `python -m tools.network_evaluation`.\n\n"
        f"- Case count: {report['case_count']}\n"
        f"- Routing accuracy: {report['routing_accuracy']:.3f}\n"
        f"- Authorization accuracy: {report['authorization_accuracy']:.3f}\n"
    )
    Path(args.markdown_output).write_text(markdown, encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
