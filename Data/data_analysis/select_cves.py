import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
CHROMA_GET_BATCH_SIZE = 300
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def get_severity(record: dict[str, object]) -> str:
    """Return a normalized severity label from a normalized CVE record."""

    cvss = record.get("cvss")
    if isinstance(cvss, dict):
        severity = cvss.get("severity")
        if isinstance(severity, str):
            normalized = severity.upper()
            if normalized in SEVERITY_ORDER:
                return normalized
    return "UNKNOWN"


def allocate_counts(
    capacities: dict[str, int],
    count: int,
) -> dict[str, int]:
    """Allocate a balanced count across severity buckets, redistributing shortages."""

    allocation = {severity: 0 for severity in capacities}
    remaining = count
    active = [severity for severity in capacities if capacities[severity] > 0]

    while remaining and active:
        share, extra = divmod(remaining, len(active))
        allocated = 0

        for index, severity in enumerate(active):
            desired = share + (index < extra)
            available = capacities[severity] - allocation[severity]
            take = min(desired, available)
            allocation[severity] += take
            allocated += take

        remaining -= allocated
        active = [
            severity
            for severity in active
            if allocation[severity] < capacities[severity]
        ]

    return allocation


def get_existing_ids(collection, ids: list[str]) -> set[str]:
    """Look up IDs in Chroma without exceeding its per-request record quota."""

    existing_ids: set[str] = set()
    for start in range(0, len(ids), CHROMA_GET_BATCH_SIZE):
        batch = ids[start : start + CHROMA_GET_BATCH_SIZE]
        existing_ids.update(collection.get(ids=batch, include=[])["ids"])
    return existing_ids


def select_cves(
    input_file: Path,
    output_file: Path,
    count: int = 1000,
    seed: int = 42,
) -> int:
    """Write a reproducible random sample of CVE JSONL records."""

    if count <= 0:
        raise ValueError("The number of CVEs to select must be positive.")

    if input_file.resolve() == output_file.resolve():
        raise ValueError("Input and output files must be different.")

    records: list[dict[str, object]] = []

    with input_file.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue

            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError(
                    f"Expected a JSON object on line {line_number} of {input_file}."
                )
            records.append(record)

    if len(records) < count:
        raise ValueError(
            f"Cannot select {count} CVEs: only {len(records)} records are available."
        )

    records_by_severity: dict[str, list[dict[str, object]]] = defaultdict(list)
    for record in records:
        records_by_severity[get_severity(record)].append(record)

    severity_groups = {
        severity: records_by_severity[severity]
        for severity in SEVERITY_ORDER
        if records_by_severity[severity]
    }
    allocation = allocate_counts(
        {severity: len(group) for severity, group in severity_groups.items()},
        count,
    )

    rng = random.Random(seed)
    selected = [
        record
        for severity, group in severity_groups.items()
        for record in rng.sample(group, allocation[severity])
    ]
    rng.shuffle(selected)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as output:
        for record in selected:
            output.write(json.dumps(record) + "\n")

    print(f"Selected {count} CVEs from {input_file}")
    print(
        "Severity counts: "
        + ", ".join(
            f"{severity}={allocation[severity]}"
            for severity in severity_groups
        )
    )
    print(f"Output: {output_file}")
    print(f"Random seed: {seed}")
    return count


def ingest_selected_cves(
    input_file: Path,
    batch_size: int = 64,
) -> int:
    """Resumably embed selected CVEs locally and store them in local Chroma."""

    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env")

    from tools.RAG.ingest import processing

    if batch_size <= 0:
        raise ValueError("batch_size must be greater than zero.")

    documents = processing.load_docs(input_file)
    if not documents:
        raise ValueError(f"No valid CVE documents found in {input_file}.")

    chunks = processing.chunk_docs(documents, chunk_size=800, chunk_overlap=100)
    if any(
        not isinstance(chunk.metadata.get("cve_id"), str)
        or not chunk.metadata["cve_id"]
        for chunk in chunks
    ):
        raise ValueError("Every selected CVE must have a non-empty cve_id.")

    store = processing.get_chroma_store(
        collection_name=processing.COLLECTION_NAME,
        local=True,
    )
    ids = [
        f"{chunk.metadata['cve_id']}:{chunk.metadata['chunk_index']}"
        for chunk in chunks
    ]
    if len(set(ids)) != len(ids):
        raise ValueError("Selected CVE chunks contain duplicate IDs.")

    legacy_ids = [str(document.metadata["cve_id"]) for document in documents]
    already_stored = get_existing_ids(
        store._collection,
        list(dict.fromkeys([*ids, *legacy_ids])),
    )
    pending = [
        (chunk, record_id)
        for chunk, record_id in zip(chunks, ids)
        if record_id not in already_stored
        and chunk.metadata["cve_id"] not in already_stored
    ]
    skipped = len(chunks) - len(pending)
    if skipped:
        print(f"Skipping {skipped} CVE chunks already stored in Chroma.")
    if not pending:
        print("All selected CVEs are already stored.")
        return 0

    for start in range(0, len(pending), batch_size):
        batch = pending[start : start + batch_size]
        batch_documents = [document for document, _ in batch]
        batch_ids = [record_id for _, record_id in batch]
        print(
            f"Embedding batch {start // batch_size + 1}: {len(batch_documents)} "
            f"chunks ({start + len(batch_documents)}/{len(pending)} pending)."
        )
        store.add_documents(
            batch_documents,
            ids=batch_ids,
        )

    print(
        f"Embedded and stored {len(pending)} CVE chunks in Chroma collection "
        f"'{processing.COLLECTION_NAME}'."
    )
    return len(pending)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Select a reproducible random sample from filtered CVEs."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("Data/processed/nvd_filtered.jsonl"),
        help="Path to the filtered CVE JSONL file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("Data/processed/nvd_selected.jsonl"),
        help="Path to write the selected CVE JSONL records.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of CVEs to select (default: 1000).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible selection (default: 42).",
    )
    parser.add_argument(
        "--ingest",
        action="store_true",
        help=(
            "Embed selected CVEs with a local Hugging Face model and store "
            "in local Chroma. Does not require Chroma Cloud credentials."
        ),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=64,
        help="CVE chunks to embed per batch (default: 64).",
    )
    args = parser.parse_args()

    select_cves(args.input, args.output, args.count, args.seed)
    if args.ingest:
        ingest_selected_cves(args.output, batch_size=args.batch_size)


if __name__ == "__main__":
    main()