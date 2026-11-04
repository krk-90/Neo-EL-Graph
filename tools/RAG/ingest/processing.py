import json
import os
from importlib.util import find_spec
from pathlib import Path
from typing import Iterable, List, Sequence

from dotenv import load_dotenv
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma

PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")

try:
    from langchain_huggingface import (
        HuggingFaceEmbeddings,
        HuggingFaceEndpointEmbeddings,
    )
except ImportError as exc:  # pragma: no cover - dependency availability
    HuggingFaceEmbeddings = None
    HuggingFaceEndpointEmbeddings = None
    _huggingface_embeddings_import_error = exc
else:
    _huggingface_embeddings_import_error = None

try:
    import chromadb
except ImportError as exc:  # pragma: no cover - dependency availability
    chromadb = None
    _chromadb_import_error = exc
else:
    _chromadb_import_error = None

DEFAULT_DATA_PATH = PROJECT_ROOT / "Data" / "processed" / "nvd_filtered.jsonl"
COLLECTION_NAME = os.environ.get("CHROMA_COLLECTION", "cve_huggingface_minilm")


def get_default_data_path() -> Path:
    return DEFAULT_DATA_PATH


def _ensure_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def _document_from_record(record: dict[str, object]) -> Document | None:
    if not isinstance(record, dict):
        return None

    cve_id = record.get("cve_id") or record.get("id") or record.get("CVE")
    description = record.get("description") or record.get("summary") or record.get("text") or ""
    summary = _ensure_text(description).strip()
    if not summary and cve_id is None:
        return None

    cvss = record.get("cvss") or {}
    if not isinstance(cvss, dict):
        cvss = {}

    severity = record.get("severity") or cvss.get("severity") or "UNKNOWN"
    if isinstance(severity, str):
        severity = severity.upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        severity = "UNKNOWN"

    cwe_ids = record.get("cwe_ids") or record.get("cwes")
    if isinstance(cwe_ids, (list, tuple, set)):
        cwe_ids = ", ".join(str(cwe_id) for cwe_id in cwe_ids)

    metadata = {
        "source": str(record.get("source") or "nvd_jsonl"),
        "cve_id": str(cve_id) if cve_id is not None else None,
        "severity": severity,
        "cvss_score": record.get("cvss_score") or cvss.get("score"),
        "cwe_ids": cwe_ids,
        "published": record.get("published"),
    }
    content = "\n".join(
        part for part in [
            f"CVE ID: {cve_id}" if cve_id else None,
            summary,
            f"Severity: {metadata['severity']}" if metadata['severity'] else None,
            f"CVSS Score: {metadata['cvss_score']}" if metadata['cvss_score'] is not None else None,
            f"CWE IDs: {metadata['cwe_ids']}" if metadata["cwe_ids"] else None,
            f"Affected products: {record.get('affected_products')}" if record.get('affected_products') else None,
            f"References: {record.get('references')}" if record.get('references') else None,
        ] if part
    )

    return Document(page_content=content, metadata={k: v for k, v in metadata.items() if v is not None})


def load_docs(path: str | os.PathLike | None = None) -> List[Document]:
    source = Path(path) if path is not None else DEFAULT_DATA_PATH
    source = Path(source)
    if not source.exists():
        raise FileNotFoundError(f"Data file not found: {source}")

    documents: List[Document] = []
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number} of {source}."
                ) from exc
            if not isinstance(record, dict):
                raise ValueError(
                    f"Expected a JSON object on line {line_number} of {source}."
                )
            doc = _document_from_record(record)
            if doc is not None:
                documents.append(doc)
    if not documents:
        raise ValueError(f"No valid CVE records found in {source}.")
    return documents


def chunk_docs(
    docs: Sequence[Document],
    chunk_size: int = 500,
    chunk_overlap: int = 80,
) -> List[Document]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero.")
    if chunk_overlap < 0 or chunk_overlap >= chunk_size:
        raise ValueError("chunk_overlap must be between zero and chunk_size.")

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", ". ", " ", ""],
    )
    chunked: List[Document] = []
    for doc in docs:
        text_chunks = splitter.split_text(doc.page_content)
        for index, chunk in enumerate(text_chunks):
            metadata = dict(doc.metadata)
            metadata["chunk_index"] = index
            metadata["chunk_count"] = len(text_chunks)
            chunked.append(Document(page_content=chunk, metadata=metadata))
    return chunked


def get_embeddings(mode: str | None = None):
    if HuggingFaceEmbeddings is None:
        raise RuntimeError(
            "Hugging Face embeddings are unavailable. Install the project requirements."
        ) from _huggingface_embeddings_import_error
    model = os.getenv(
        "HF_EMBEDDING_MODEL",
        "sentence-transformers/all-MiniLM-L6-v2",
    )
    mode = (mode or os.getenv("HF_EMBEDDING_MODE", "local")).strip().lower()
    if mode == "endpoint":
        if HuggingFaceEndpointEmbeddings is None:
            raise RuntimeError(
                "Hugging Face endpoint embeddings are unavailable. "
                "Install the project requirements."
            ) from _huggingface_embeddings_import_error
        token = os.getenv("HUGGINGFACEHUB_API_TOKEN") or os.getenv("HF_TOKEN")
        if not token:
            raise RuntimeError(
                "Hosted Hugging Face embeddings require HUGGINGFACEHUB_API_TOKEN "
                "or HF_TOKEN. Set HF_EMBEDDING_MODE=local to use the local model."
            )
        return HuggingFaceEndpointEmbeddings(
            model=model,
            task="feature-extraction",
            huggingfacehub_api_token=token,
        )
    if mode != "local":
        raise ValueError("HF_EMBEDDING_MODE must be 'local' or 'endpoint'.")
    if find_spec("sentence_transformers") is None:
        raise RuntimeError(
            "The local Hugging Face model runtime is not installed. Install "
            "`sentence-transformers` to run locally, or set "
            "HF_EMBEDDING_MODE=endpoint with a Hugging Face token to avoid "
            "downloading PyTorch and the model."
        )
    return HuggingFaceEmbeddings(
        model_name=model,
        encode_kwargs={"normalize_embeddings": True},
    )


def get_chroma_store(
    collection_name: str = COLLECTION_NAME,
    persist_directory: str | None = None,
    local: bool = False,
):
    if not collection_name.strip():
        raise ValueError("Chroma collection name must not be empty.")

    embeddings = get_embeddings(mode="local" if local else None)
    api_key = os.getenv("CHROMA_API_KEY")
    if api_key and not local:
        missing = [
            name for name in ("CHROMA_TENANT", "CHROMA_DATABASE")
            if not os.getenv(name)
        ]
        if missing:
            raise RuntimeError(
                "Chroma Cloud credentials are incomplete; set "
                + ", ".join(missing)
                + "."
            )
        if chromadb is None:
            raise RuntimeError(
                "Chroma Cloud support is unavailable. Install the project requirements."
            ) from _chromadb_import_error
        client = chromadb.CloudClient(
            api_key=api_key,
            tenant=os.environ["CHROMA_TENANT"],
            database=os.environ["CHROMA_DATABASE"],
        )
        return Chroma(
            client=client,
            collection_name=collection_name,
            embedding_function=embeddings,
        )

    storage_path = Path(
        persist_directory
        or os.environ.get("CHROMA_PERSIST_DIRECTORY")
        or PROJECT_ROOT / "Database" / "chroma_db"
    )
    if not storage_path.is_absolute():
        storage_path = PROJECT_ROOT / storage_path
    storage_path.mkdir(parents=True, exist_ok=True)
    return Chroma(
        collection_name=collection_name,
        embedding_function=embeddings,
        persist_directory=str(storage_path),
    )


def store_docs(
    docs: Iterable[Document],
    collection_name: str = COLLECTION_NAME,
    persist_directory: str | None = None,
    batch_size: int = 500,
):
    if batch_size <= 0:
        raise ValueError("batch_size must be greater than zero.")

    records = list(docs)
    if not records:
        return get_chroma_store(
            collection_name=collection_name,
            persist_directory=persist_directory,
        )

    ids = []
    for document in records:
        cve_id = document.metadata.get("cve_id")
        if not isinstance(cve_id, str) or not cve_id:
            raise ValueError("Every indexed CVE document must have a cve_id.")
        chunk_index = document.metadata.get("chunk_index", 0)
        ids.append(f"{cve_id}:{chunk_index}")
    if len(set(ids)) != len(ids):
        raise ValueError("CVE document IDs must be unique before indexing.")

    store = get_chroma_store(
        collection_name=collection_name,
        persist_directory=persist_directory,
    )
    for start in range(0, len(records), batch_size):
        batch = records[start:start + batch_size]
        store.add_documents(batch, ids=ids[start:start + batch_size])
    return store


def ingest_data(
    path: str | os.PathLike | None = None,
    collection_name: str = COLLECTION_NAME,
    chunk_size: int = 500,
    chunk_overlap: int = 80,
    batch_size: int = 500,
):
    records = load_docs(path)
    chunks = chunk_docs(records, chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    return store_docs(
        chunks,
        collection_name=collection_name,
        batch_size=batch_size,
    )
