from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .brain.engine import BrainEngine
from .brain.models import FeedbackRequest, IngestRequest, InvestigationRequest
from .brain.store import BrainStore

app = FastAPI(title="Neo-EL-Graph", version="0.1.0", description="Evidence-aware cybersecurity intelligence brain prototype")
store = BrainStore()
brain = BrainEngine(store)
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/health")
def health():
    return {"status": "ok", "service": "neo-el-graph", "version": "0.1.0"}

@app.get("/api/brain/overview")
def overview():
    return store.get_overview()

@app.get("/api/graph")
def graph(limit: int = 500):
    if not 1 <= limit <= 1000:
        raise HTTPException(400, "limit must be between 1 and 1000")
    return store.graph(limit)

@app.post("/api/knowledge/ingest")
def ingest(payload: IngestRequest):
    try:
        return {"status": "ingested", **store.ingest(payload.source, [e.model_dump() for e in payload.entities], [r.model_dump() for r in payload.relationships])}
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

@app.post("/api/investigate")
def investigate(payload: InvestigationRequest):
    return brain.investigate(payload.query, payload.entity_ids, payload.max_hops, payload.include_unverified)

@app.post("/api/feedback")
def feedback(payload: FeedbackRequest):
    try:
        store.add_feedback(payload.investigation_id, payload.verdict, payload.notes)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"status": "recorded", "verdict": payload.verdict, "learning_mode": "outcome_tracking_only"}

@app.post("/api/demo/seed")
def seed_demo():
    if store.get_overview()["nodes"] > 0:
        return {"status": "skipped", "message": "Graph already contains data; demo seed will not overwrite it."}
    entities = [
        {"id":"demo-repo","type":"Repository","label":"demo-payment-service","properties":{"language":"Python","demo":True},"source_url":None,"confidence":0.5,"verified":False},
        {"id":"demo-package","type":"Package","label":"demo-parser","properties":{"version":"1.2.0","demo":True},"source_url":None,"confidence":0.5,"verified":False},
        {"id":"demo-vuln","type":"Vulnerability","label":"DEMO-2026-001","properties":{"severity":"high","description":"Synthetic example only; not a real advisory."},"source_url":None,"confidence":0.5,"verified":False},
        {"id":"demo-technique","type":"Technique","label":"Input parsing abuse","properties":{"demo":True},"source_url":None,"confidence":0.4,"verified":False},
        {"id":"demo-evidence","type":"Evidence","label":"Synthetic test fixture","properties":{"warning":"This evidence is fabricated for UI demonstration."},"source_url":None,"confidence":0.4,"verified":False},
    ]
    edges = [
        {"source":"demo-repo","target":"demo-package","type":"DEPENDS_ON","properties":{"demo":True},"source_url":None,"confidence":0.5,"verified":False},
        {"source":"demo-package","target":"demo-vuln","type":"POTENTIALLY_AFFECTED_BY","properties":{"demo":True},"source_url":None,"confidence":0.5,"verified":False},
        {"source":"demo-vuln","target":"demo-technique","type":"MAY_RELATE_TO","properties":{"demo":True},"source_url":None,"confidence":0.4,"verified":False},
        {"source":"demo-vuln","target":"demo-evidence","type":"HAS_SYNTHETIC_EVIDENCE","properties":{"demo":True},"source_url":None,"confidence":0.4,"verified":False},
    ]
    return {"status":"seeded", **store.ingest("synthetic-demo-fixture", entities, edges), "warning":"All demo nodes and relationships are synthetic and unverified."}
