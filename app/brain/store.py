import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_DB = os.getenv("NEOEL_DB_PATH", "./data/neoel.db")


class BrainStore:
    """Small persistent graph store; designed to be replaceable by a Neo4j adapter."""

    def __init__(self, db_path: str = DEFAULT_DB) -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_db(self) -> None:
        with self.connect() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL,
                    properties TEXT NOT NULL DEFAULT '{}', source_url TEXT,
                    source TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 0.7,
                    verified INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, target TEXT NOT NULL,
                    type TEXT NOT NULL, properties TEXT NOT NULL DEFAULT '{}', source_url TEXT,
                    confidence REAL NOT NULL DEFAULT 0.7, verified INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(source, target, type, source_url),
                    FOREIGN KEY(source) REFERENCES nodes(id), FOREIGN KEY(target) REFERENCES nodes(id)
                );
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY, query TEXT NOT NULL, result TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL,
                    verdict TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)

    def ingest(self, source: str, entities: list[dict[str, Any]], relationships: list[dict[str, Any]]) -> dict[str, int]:
        with self.connect() as c:
            for e in entities:
                c.execute("""INSERT INTO nodes(id,type,label,properties,source_url,source,confidence,verified,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
                    ON CONFLICT(id) DO UPDATE SET type=excluded.type,label=excluded.label,
                    properties=excluded.properties,source_url=excluded.source_url,source=excluded.source,
                    confidence=excluded.confidence,verified=MAX(nodes.verified,excluded.verified),updated_at=CURRENT_TIMESTAMP""",
                    (e["id"], e["type"], e["label"], json.dumps(e.get("properties", {})), e.get("source_url"), source, e.get("confidence", .7), int(e.get("verified", False))))
            for edge in relationships:
                exists = c.execute("SELECT 1 FROM nodes WHERE id IN (?,?)", (edge["source"], edge["target"])).fetchall()
                if len(exists) != 2:
                    raise ValueError(f"Relationship endpoints must exist: {edge['source']} -> {edge['target']}")
                c.execute("""INSERT INTO edges(source,target,type,properties,source_url,confidence,verified)
                    VALUES(?,?,?,?,?,?,?) ON CONFLICT(source,target,type,source_url) DO UPDATE SET
                    properties=excluded.properties,confidence=excluded.confidence,
                    verified=MAX(edges.verified,excluded.verified)""",
                    (edge["source"], edge["target"], edge["type"], json.dumps(edge.get("properties", {})), edge.get("source_url"), edge.get("confidence", .7), int(edge.get("verified", False))))
        return {"entities_upserted": len(entities), "relationships_upserted": len(relationships)}

    def graph(self, limit: int = 500) -> dict[str, Any]:
        with self.connect() as c:
            nodes = c.execute("SELECT * FROM nodes ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
            ids = [n["id"] for n in nodes]
            if not ids:
                return {"nodes": [], "edges": []}
            placeholders = ",".join("?" for _ in ids)
            edges = c.execute(f"SELECT * FROM edges WHERE source IN ({placeholders}) AND target IN ({placeholders}) LIMIT ?", (*ids, *ids, limit * 2)).fetchall()
        return {"nodes": [self._node(n) for n in nodes], "edges": [self._edge(e) for e in edges]}

    def get_overview(self) -> dict[str, Any]:
        with self.connect() as c:
            counts = {table: c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("nodes", "edges", "investigations", "feedback")}
            feedback = c.execute("SELECT verdict,COUNT(*) n FROM feedback GROUP BY verdict").fetchall()
        verdicts = {r["verdict"]: r["n"] for r in feedback}
        reviewed = sum(verdicts.values())
        correct = verdicts.get("correct", 0)
        return {**counts, "feedback_verdicts": verdicts, "feedback_correct_rate": round(correct / reviewed, 3) if reviewed else None,
                "learning_status": "collecting_outcomes" if reviewed < 10 else "ready_for_evaluation",
                "note": "Feedback is tracked; no model or policy is automatically changed by this prototype."}

    def investigate(self, investigation_id: str, query: str, entity_ids: list[str], max_hops: int, include_unverified: bool) -> dict[str, Any]:
        graph = self.graph(limit=1000)
        nodes = {n["id"]: n for n in graph["nodes"]}
        query_terms = {t.lower() for t in query.replace("/", " ").replace("-", " ").split() if len(t) > 2}
        seeds = set(entity_ids)
        for node in graph["nodes"]:
            haystack = (node["label"] + " " + node["type"] + " " + json.dumps(node["properties"])).lower()
            if any(term in haystack for term in query_terms):
                seeds.add(node["id"])
        seeds = {s for s in seeds if s in nodes}
        visited = set(seeds)
        selected_edges: list[dict[str, Any]] = []
        frontier = set(seeds)
        for _ in range(max_hops):
            next_frontier = set()
            for edge in graph["edges"]:
                if not include_unverified and not edge["verified"]:
                    continue
                if edge["source"] in frontier or edge["target"] in frontier:
                    selected_edges.append(edge)
                    other = edge["target"] if edge["source"] in frontier else edge["source"]
                    if other not in visited:
                        next_frontier.add(other)
            visited.update(next_frontier)
            frontier = next_frontier
            if not frontier:
                break
        result_nodes = [nodes[n] for n in visited if n in nodes and (include_unverified or nodes[n]["verified"])]
        visible_ids = {node["id"] for node in result_nodes}
        visible_edges = [edge for edge in selected_edges if edge["source"] in visible_ids and edge["target"] in visible_ids]
        visible_seeds = [nodes[s] for s in seeds if include_unverified or nodes[s]["verified"]]
        result = {
            "investigation_id": investigation_id, "query": query,
            "matched_entities": visible_seeds,
            "nodes": result_nodes,
            "relationships": visible_edges,
            "evidence_gaps": [n["id"] for n in result_nodes if not n.get("source_url")],
            "limitations": ["Graph matches are candidate leads, not proof of exploitability.", "Only ingested data is searched.", "Unverified nodes are excluded unless explicitly requested."],
        }
        with self.connect() as c:
            c.execute("INSERT INTO investigations(id,query,result) VALUES(?,?,?)", (investigation_id, query, json.dumps(result)))
        return result

    def add_feedback(self, investigation_id: str, verdict: str, notes: str) -> None:
        with self.connect() as c:
            if not c.execute("SELECT 1 FROM investigations WHERE id=?", (investigation_id,)).fetchone():
                raise KeyError("Investigation not found")
            c.execute("INSERT INTO feedback(investigation_id,verdict,notes) VALUES(?,?,?)", (investigation_id, verdict, notes))

    @staticmethod
    def _node(n: sqlite3.Row) -> dict[str, Any]:
        return {"id": n["id"], "type": n["type"], "label": n["label"], "properties": json.loads(n["properties"]),
                "source_url": n["source_url"], "source": n["source"], "confidence": n["confidence"],
                "verified": bool(n["verified"]), "updated_at": n["updated_at"]}

    @staticmethod
    def _edge(e: sqlite3.Row) -> dict[str, Any]:
        return {"id": e["id"], "source": e["source"], "target": e["target"], "type": e["type"],
                "properties": json.loads(e["properties"]), "source_url": e["source_url"],
                "confidence": e["confidence"], "verified": bool(e["verified"]), "created_at": e["created_at"]}
