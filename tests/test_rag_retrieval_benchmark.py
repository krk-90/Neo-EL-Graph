import unittest
from unittest.mock import patch

from langchain_core.documents import Document

from tools.RAG.Evaluation.benchmark_retrieval import evaluate_retrieval


class RetrievalBenchmarkTests(unittest.TestCase):
    @patch(
        "tools.RAG.Evaluation.benchmark_retrieval.get_embedded_text",
        return_value={"metadatas": [{"cve_id": "CVE-B"}]},
    )
    @patch("tools.RAG.Evaluation.benchmark_retrieval.retrieve")
    def test_reports_weak_retrieval_when_relevant_cve_is_missing(
        self,
        retrieve_mock,
        _embedded_mock,
    ):
        retriever = retrieve_mock.return_value
        retriever.invoke.return_value = [
            Document(page_content="unrelated", metadata={"cve_id": "CVE-X"})
        ]
        retrieve_mock.return_value = retriever

        golden = {
            "case-a": {
                "question": "Find CVE-A",
                "relevant_ids": ["CVE-A"],
            }
        }

        report = evaluate_retrieval(golden, k=5)

        self.assertEqual(report["assessment"], "weak")
        self.assertEqual(report["aggregate"]["recall@k"], 0.0)
        self.assertFalse(report["cases"][0]["index_coverage"]["CVE-A"])

    @patch(
        "tools.RAG.Evaluation.benchmark_retrieval.get_embedded_text",
        return_value={"metadatas": [{"cve_id": "CVE-A"}]},
    )
    @patch("tools.RAG.Evaluation.benchmark_retrieval.retrieve")
    def test_reports_perfect_retrieval_for_indexed_first_result(
        self,
        retrieve_mock,
        _embedded_mock,
    ):
        retrieve_mock.return_value.invoke.return_value = [
            Document(page_content="CVE-A", metadata={"cve_id": "CVE-A"})
        ]
        golden = {
            "case-a": {
                "question": "Find CVE-A",
                "relevant_ids": ["CVE-A"],
            }
        }

        report = evaluate_retrieval(golden, k=5)

        self.assertEqual(report["assessment"], "strong")
        self.assertEqual(report["aggregate"]["recall@k"], 1.0)
        self.assertEqual(report["aggregate"]["mrr"], 1.0)
        self.assertTrue(report["cases"][0]["index_coverage"]["CVE-A"])


if __name__ == "__main__":
    unittest.main()
