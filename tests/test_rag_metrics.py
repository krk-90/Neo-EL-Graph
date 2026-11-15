import unittest
from tools.RAG.Evaluation.metrics import citation_coverage, exact_match, ndcg_at_k, precision_at_k, recall_at_k, reciprocal_rank, token_f1

class RetrievalMetricTests(unittest.TestCase):
    def test_precision_recall(self):
        retrieved, relevant = ["CVE-A", "CVE-X", "CVE-B"], {"CVE-A", "CVE-B"}
        self.assertAlmostEqual(precision_at_k(retrieved, relevant, 2), 0.5)
        self.assertAlmostEqual(recall_at_k(retrieved, relevant, 2), 0.5)
    def test_reciprocal_rank(self):
        self.assertAlmostEqual(reciprocal_rank(["x", "target"], {"target"}), 0.5)
        self.assertEqual(reciprocal_rank(["x"], {"target"}), 0.0)
    def test_ndcg_perfect_ranking(self):
        self.assertAlmostEqual(ndcg_at_k(["a", "b"], {"a", "b"}, 2), 1.0)
    def test_invalid_k(self):
        with self.assertRaises(ValueError): precision_at_k([], set(), 0)

class GenerationMetricTests(unittest.TestCase):
    def test_exact_match_ignores_case_and_whitespace(self):
        self.assertEqual(exact_match("Hello  WORLD", "hello world"), 1.0)
    def test_token_f1_perfect(self):
        self.assertAlmostEqual(token_f1("a b c", "a b c"), 1.0)
    def test_citation_coverage(self):
        self.assertAlmostEqual(citation_coverage("CVE-2021-44228", {"CVE-2021-44228", "CVE-2020-1"}), 0.5)

if __name__ == "__main__": unittest.main()
