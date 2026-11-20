"""Orchestrator entry point for direct NVD API lookups."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.nvd_api_agent import NVDApiAgent


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query the NVD 2.0 API directly."
    )
    parser.add_argument("query", nargs="+", help="CVE ID or keyword search")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    )
    args = parser.parse_args()

    result = NVDApiAgent().ask(
        " ".join(args.query),
        limit=args.limit,
        severity=args.severity,
    )
    print(json.dumps({
        "query": result.query,
        "cve_ids": list(result.cve_ids),
        "vulnerabilities": list(result.vulnerabilities),
    }, indent=2))


if __name__ == "__main__":
    main()