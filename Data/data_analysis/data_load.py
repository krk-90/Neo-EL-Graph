#!/usr/bin/env python3
"""
Read an NVD JSON dataset (nvd.json) and flatten it into simple records.

Supports both formats:
  * NVD 1.1 feeds  -> top-level key "CVE_Items"
  * NVD 2.0 API    -> top-level key "vulnerabilities"

Usage:
    python read_nvd.py nvd.json
    python read_nvd.py nvd.json --min-score 9.0
    python read_nvd.py nvd.json --search openssl --limit 20
    python read_nvd.py nvd.json --csv out.csv
"""

import argparse
import csv
import json
import sys
from collections import Counter


def load_json(path):
    """Load a JSON file. Falls back to JSON Lines if a normal load fails."""
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            f.seek(0)
            return [json.loads(line) for line in f if line.strip()]


def english(descriptions):
    """Pick the English description from a list of {lang, value} dicts."""
    for d in descriptions or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def parse_v2(item):
    """Parse one entry from the NVD 2.0 API format."""
    cve = item.get("cve", item)
    score = severity = vector = None

    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or m.get("baseSeverity")
            vector = data.get("vectorString")
            break

    cwes = [
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
    ]

    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": english(cve.get("descriptions")),
        "cvss_score": score,
        "severity": severity,
        "vector": vector,
        "cwes": ";".join(cwes),
    }


def parse_v11(item):
    """Parse one entry from the legacy NVD 1.1 feed format."""
    cve = item.get("cve", {})
    meta = cve.get("CVE_data_meta", {})
    desc = cve.get("description", {}).get("description_data", [])
    impact = item.get("impact", {})

    score = severity = vector = None
    if "baseMetricV3" in impact:
        data = impact["baseMetricV3"].get("cvssV3", {})
        score, severity, vector = (
            data.get("baseScore"),
            data.get("baseSeverity"),
            data.get("vectorString"),
        )
    elif "baseMetricV2" in impact:
        m = impact["baseMetricV2"]
        data = m.get("cvssV2", {})
        score, severity, vector = (
            data.get("baseScore"),
            m.get("severity"),
            data.get("vectorString"),
        )

    cwes = [
        d.get("value")
        for pt in cve.get("problemtype", {}).get("problemtype_data", [])
        for d in pt.get("description", [])
    ]

    return {
        "id": meta.get("ID"),
        "published": item.get("publishedDate"),
        "modified": item.get("lastModifiedDate"),
        "status": None,
        "description": english(desc),
        "cvss_score": score,
        "severity": severity,
        "vector": vector,
        "cwes": ";".join(c for c in cwes if c),
    }


def parse_nvd(data):
    """Detect the format and return a list of flat records."""
    if isinstance(data, dict):
        if "vulnerabilities" in data:          # 2.0 API
            return [parse_v2(v) for v in data["vulnerabilities"]]
        if "CVE_Items" in data:                # 1.1 feed
            return [parse_v11(v) for v in data["CVE_Items"]]
        raise ValueError(
            "Unrecognized NVD format. Top-level keys: " + ", ".join(data.keys())
        )
    if isinstance(data, list):                 # JSON Lines / plain list
        return [parse_v2(v) if "cve" in v and "id" in v["cve"] else parse_v11(v)
                for v in data]
    raise ValueError("Unexpected JSON structure")


def main():
    ap = argparse.ArgumentParser(description="Read an NVD JSON dataset")
    ap.add_argument("path", nargs="?", default="nvd.json", help="path to nvd.json")
    ap.add_argument("--min-score", type=float, help="only CVEs with CVSS >= this")
    ap.add_argument("--search", help="case-insensitive keyword in description")
    ap.add_argument("--limit", type=int, default=10, help="records to print")
    ap.add_argument("--csv", help="write all matching records to this CSV file")
    args = ap.parse_args()

    try:
        records = parse_nvd(load_json(args.path))
    except FileNotFoundError:
        sys.exit(f"File not found: {args.path}")
    except (ValueError, json.JSONDecodeError) as e:
        sys.exit(f"Could not read dataset: {e}")

    print(f"Loaded {len(records):,} CVE records from {args.path}")
    records = [r for r in records if r["status"] != "Rejected"]
    print(f"{len(records):,} records after removing rejected CVEs")
    # Filters
    if args.min_score is not None:
        records = [r for r in records
                   if r["cvss_score"] is not None and r["cvss_score"] >= args.min_score]
    if args.search:
        kw = args.search.lower()
        records = [r for r in records if kw in (r["description"] or "").lower()]
    if args.min_score is not None or args.search:
        print(f"{len(records):,} records match filters")

    # Summary
    sev = Counter(r["severity"] or "UNKNOWN" for r in records)
    print("\nSeverity breakdown:")
    for name, count in sev.most_common():
        print(f"  {name:<10} {count:,}")

    # Preview
    print(f"\nFirst {min(args.limit, len(records))} records:")
    for r in records[: args.limit]:
        desc = (r["description"] or "").replace("\n", " ")
        print(f"- {r['id']}  [{r['severity'] or 'N/A'} {r['cvss_score'] if r['cvss_score'] is not None else ''}]  {desc[:110]}...")
    # Optional CSV export
    if args.csv and records:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
            writer.writeheader()
            writer.writerows(records)
        print(f"\nWrote {len(records):,} records to {args.csv}")


if __name__ == "__main__":
    main()