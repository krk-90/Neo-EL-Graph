import json
from pathlib import Path

INPUT_FILE = Path("Data/processed/nvd_normalized.jsonl")
OUTPUT_FILE = Path("Data/processed/nvd_filtered.jsonl")


def filter_records():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    kept = 0
    rejected = 0

    with INPUT_FILE.open("r", encoding="utf-8") as source, \
         OUTPUT_FILE.open("w", encoding="utf-8") as output:

        for line in source:
            record = json.loads(line)
            total += 1

            status = (record.get("vuln_status") or "").lower()
            description = record.get("description", "").lower()

            is_rejected = (
                status == "rejected"
                or description.startswith("rejected reason:")
            )

            if is_rejected:
                rejected += 1
                continue

            output.write(json.dumps(record) + "\n")
            kept += 1

    print("\n========== FILTER RESULTS ==========")
    print("Original records:", total)
    print("Rejected records removed:", rejected)
    print("Records retained:", kept)
    print("Output:", OUTPUT_FILE)
    print("====================================")


if __name__ == "__main__":
    filter_records()
