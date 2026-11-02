import argparse
import json
import ijson

from pathlib import Path


def get_description(cve):
    """Extract the English vulnerability description."""

    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "")

    return ""


def get_cvss(cve):
    """Extract the highest-priority available CVSS metric."""

    metrics = cve.get("metrics", {})

    metric_types = (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    )

    for metric_type in metric_types:
        entries = metrics.get(metric_type, [])

        if not entries:
            continue

        data = entries[0].get("cvssData", {})

        return {
            "version": data.get("version"),
            "score": data.get("baseScore"),
            "severity": data.get(
                "baseSeverity",
                entries[0].get("baseSeverity")
            ),
        }

    return None


def get_weaknesses(cve):
    """Extract unique CWE identifiers."""

    weaknesses = set()

    for item in cve.get("weaknesses", []):
        for description in item.get("description", []):
            value = description.get("value", "")

            if value.startswith("CWE-"):
                weaknesses.add(value)

    return sorted(weaknesses)


def get_affected_products(cve):
    """Extract affected vendors, products, versions and statuses."""

    products = []

    for item in cve.get("affected", []):
        # NVD feed structure
        affected_data = item.get("affectedData", [])

        for affected in affected_data:
            versions = [
                {
                    "version": version.get("version"),
                    "status": version.get("status"),
                }
                for version in affected.get("versions", [])
            ]

            products.append({
                "vendor": affected.get("vendor"),
                "product": affected.get("product"),
                "versions": versions,
            })

    return products


def get_references(cve):
    """Extract unique reference URLs while preserving order."""

    references = [
        ref.get("url")
        for ref in cve.get("references", [])
        if ref.get("url")
    ]

    return list(dict.fromkeys(references))


def normalize(record):
    """Convert an NVD vulnerability record into a consistent structure."""

    cve = record.get("cve", record)

    return {
        "cve_id": cve.get("id"),
        "description": get_description(cve),
        "cvss": get_cvss(cve),
        "cwe_ids": get_weaknesses(cve),
        "affected_products": get_affected_products(cve),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "references": get_references(cve),
    }


def find_array_key(file_path):
    """Detect the top-level JSON array using streaming parsing."""

    with open(file_path, "rb") as file:
        parser = ijson.parse(file)

        for prefix, event, value in parser:
            if prefix == "" and event == "map_key":
                key = value

            elif event == "start_array" and prefix == key:
                return key

    raise ValueError("Could not find a top-level JSON array.")


def process(input_file, output_file):
    """Stream NVD records and write normalized JSONL output."""

    input_path = Path(input_file)
    output_path = Path(output_file)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Automatically create output directories.
    output_path.parent.mkdir(parents=True, exist_ok=True)

    array_key = find_array_key(input_path)

    print(f"Input: {input_path}")
    print(f"Detected array: {array_key}")
    print("Starting normalization...")

    count = 0
    skipped = 0

    with open(input_path, "rb") as source, \
         open(output_path, "w", encoding="utf-8") as output:

        for record in ijson.items(source, f"{array_key}.item"):

            normalized = normalize(record)

            if not normalized["cve_id"]:
                skipped += 1
                continue

            output.write(
                json.dumps(normalized, default=float) + "\n"
            )

            count += 1

            if count % 1000 == 0:
                print(f"Processed: {count} CVEs")

    print("\nNormalization complete.")
    print(f"Records saved: {count}")
    print(f"Records skipped: {skipped}")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Normalize NVD vulnerability JSON data."
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to the NVD JSON input file."
    )

    parser.add_argument(
        "--output",
        default="Data/processed/nvd_normalized.jsonl",
        help="Path to the normalized JSONL output."
    )

    args = parser.parse_args()

    process(args.input, args.output)
