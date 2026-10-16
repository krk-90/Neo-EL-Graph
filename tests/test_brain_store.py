import tempfile
import unittest
from pathlib import Path
from app.brain.store import BrainStore


class BrainStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = BrainStore(str(Path(self.temp.name) / "test.db"))

    def tearDown(self):
        self.temp.cleanup()

    def test_ingest_and_graph_traversal(self):
        entities = [
            {"id": "repo-a", "type": "Repository", "label": "sample-service", "properties": {}, "source_url": "https://example.test/repo", "confidence": 0.9, "verified": True},
            {"id": "pkg-a", "type": "Package", "label": "sample-parser", "properties": {"version": "1.0"}, "source_url": "https://example.test/package", "confidence": 0.9, "verified": True},
        ]
        edges = [{"source": "repo-a", "target": "pkg-a", "type": "DEPENDS_ON", "properties": {}, "source_url": "https://example.test/manifest", "confidence": 0.9, "verified": True}]
        self.store.ingest("unit-test", entities, edges)
        result = self.store.investigate("test-investigation", "sample-parser", [], 1, False)
        self.assertEqual(len(result["matched_entities"]), 1)
        self.assertEqual(len(result["nodes"]), 2)
        self.assertEqual(len(result["relationships"]), 1)

    def test_unverified_nodes_are_excluded_by_default(self):
        self.store.ingest("test", [{"id": "lead", "type": "Finding", "label": "unverified lead", "properties": {}, "source_url": None, "confidence": 0.3, "verified": False}], [])
        result = self.store.investigate("test-investigation", "unverified lead", [], 1, False)
        self.assertEqual(result["nodes"], [])
        self.assertEqual(len(result["matched_entities"]), 1)

    def test_relationship_requires_known_endpoints(self):
        with self.assertRaises(ValueError):
            self.store.ingest("test", [], [{"source": "missing-a", "target": "missing-b", "type": "RELATED_TO", "properties": {}, "source_url": None, "confidence": 0.5, "verified": False}])


if __name__ == "__main__":
    unittest.main()
