"""Fetch CVEs from the NVD 2.0 API and add them to the filtered dataset."""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable

from dotenv import load_dotenv

from Data.data_analysis.normalize_nvd import normalize

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = PROJECT_ROOT / "Data" / "processed" / "nvd_filtered.jsonl"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id: str, api_key: str | None = None, timeout: int = 30) -> dict:
    if not cve_id.strip():
        raise ValueError("CVE ID must not be empty.")

    query = urllib.parse.urlencode({"cveId": cve_id.strip().upper()})
    request = urllib.request.Request(
        f"{NVD_API_URL}?{query}",
        headers={"Accept": "application/json"},
    )
    if api_key:
        request.add_header("apiKey", api_key)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"NVD API returned HTTP {exc.code} for {cve_id}: {exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach the NVD API: {exc.reason}") from exc

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        raise RuntimeError(f"NVD API returned no record for {cve_id}.")
    return normalize(vulnerabilities[0])


def read_existing(output_path: Path) -> tuple[dict[str, dict], list[str]]:
    records: dict[str, dict] = {}
    lines: list[str] = []
    if not output_path.exists():
        return records, lines

    with output_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {output_path}"
                ) from exc
            cve_id = record.get("cve_id") or record.get("id")
            if cve_id:
                records[str(cve_id).upper()] = record
            lines.append(json.dumps(record, ensure_ascii=False))
    return records, lines


def merge_cves(
    cve_ids: Iterable[str],
    output_path: Path,
    api_key: str | None = None,
    timeout: int = 30,
) -> list[str]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    existing, _ = read_existing(output_path)
    fetched: list[str] = []

    normalized_ids = list(dict.fromkeys(
        cve_id.strip().upper() for cve_id in cve_ids if cve_id.strip()
    ))
    for index, cve_id in enumerate(normalized_ids):
        record = fetch_cve(cve_id, api_key=api_key, timeout=timeout)
        status = str(record.get("vuln_status") or "").lower()
        if status == "rejected":
            continue
        existing[cve_id] = record
        fetched.append(cve_id)
        if index + 1 < len(normalized_ids):
            time.sleep(0.6 if api_key else 6.0)

    with output_path.open("w", encoding="utf-8") as handle:
        for cve_id in sorted(existing):
            handle.write(json.dumps(existing[cve_id], ensure_ascii=False) + "\n")
    return fetched


def main() -> None:
    load_dotenv(PROJECT_ROOT / ".env")
    parser = argparse.ArgumentParser(
        description="Fetch CVEs from the NVD 2.0 API and update the RAG dataset."
    )
    parser.add_argument(
        "cve_ids",
        nargs="+",
        help="CVE IDs to fetch, for example CVE-2021-44228",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    api_key = os.getenv("NVD_API_KEY")
    fetched = merge_cves(
        args.cve_ids,
        args.output,
        api_key=api_key,
        timeout=args.timeout,
    )
    print(f"Fetched and merged {len(fetched)} CVE record(s): {', '.join(fetched)}")
    print(f"Updated dataset: {args.output}")


if __name__ == "__main__":
    main()
