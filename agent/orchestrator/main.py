"""Orchestrator entry point for direct NVD API lookups."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.nvd_api_agent import NVDApiAgent  # noqa: E402
from agent.orchestrator.graph import run_security_assessment  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run NVD lookups or authorized network assessments."
    )
    parser.add_argument(
        "query",
        nargs="+",
        help="Natural-language request for network assessment or NVD query",
    )
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    )
    parser.add_argument(
        "--target", help="Authorized hostname or IP for network assessment"
    )
    parser.add_argument("--target-range", help="Authorized CIDR range for discovery")
    parser.add_argument(
        "--authorized-target",
        action="append",
        help="Explicit authorized target or CIDR; repeat for multiple scopes",
    )
    parser.add_argument(
        "--port", action="append", type=int, help="Port to check; repeat as needed"
    )
    parser.add_argument(
        "--keyword",
        action="append",
        help="Product, service, or vulnerability keyword for NVD/RAG correlation",
    )
    args = parser.parse_args()

    if args.target or args.target_range:
        if not args.authorized_target:
            parser.error("--authorized-target is required for network assessments")
        result = run_security_assessment(
            request=" ".join(args.query),
            target=args.target,
            target_range=args.target_range,
            authorized_targets=args.authorized_target,
            ports=args.port,
            keywords=args.keyword,
        )
        print(json.dumps(result, indent=2, default=str))
        return

    result = NVDApiAgent().ask(
        " ".join(args.query),
        limit=args.limit,
        severity=args.severity,
    )
    print(
        json.dumps(
            {
                "query": result.query,
                "cve_ids": list(result.cve_ids),
                "vulnerabilities": list(result.vulnerabilities),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
