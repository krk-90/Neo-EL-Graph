import json
import tempfile
import unittest
from pathlib import Path

from langchain_core.documents import Document

from tools.RAG.ingest.processing import chunk_docs, load_docs


class ProcessingTests(unittest.TestCase):
    def test_load_filtered_jsonl_record(self):
        record = {
            "cve_id": "CVE-2021-44228",
            "description": "Remote code execution in a logging library.",
            "severity": "CRITICAL",
            "cvss": {"score": 10.0, "severity": "CRITICAL"},
            "cwe_ids": ["CWE-502"],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "filtered.jsonl"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            documents = load_docs(path)
        self.assertEqual(len(documents), 1)
        self.assertIn("CVE-2021-44228", documents[0].page_content)
        self.assertEqual(documents[0].metadata["severity"], "CRITICAL")
        self.assertEqual(documents[0].metadata["cve_id"], "CVE-2021-44228")

    def test_invalid_jsonl_reports_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.jsonl"
            path.write_text('{"cve_id":\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 1"):
                load_docs(path)

    def test_missing_file_fails_clearly(self):
        with self.assertRaises(FileNotFoundError):
            load_docs("/path/that/does/not/exist/filtered.jsonl")

    def test_chunking_preserves_metadata(self):
        document = Document(
            page_content="A" * 1200,
            metadata={"cve_id": "CVE-2021-44228", "severity": "CRITICAL"},
        )
        chunks = chunk_docs([document], chunk_size=300, chunk_overlap=30)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(chunk.metadata["cve_id"] == "CVE-2021-44228" for chunk in chunks))
        self.assertEqual(chunks[0].metadata["chunk_index"], 0)

    def test_invalid_chunk_configuration_fails(self):
        with self.assertRaises(ValueError):
            chunk_docs([], chunk_size=10, chunk_overlap=10)


if __name__ == "__main__":
    unittest.main()
