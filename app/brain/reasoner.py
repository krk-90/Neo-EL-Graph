import json
import os
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


class GroundedReasoner:
    """Optional Groq-compatible reasoning layer; only receives retrieved graph context."""

    def __init__(self) -> None:
        self.api_key = os.getenv("GROQ_API_KEY")
        self.model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.endpoint = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1/chat/completions")

    def analyze(self, query: str, graph_result: dict) -> dict:
        context = {
            "matched_entities": graph_result.get("matched_entities", []),
            "nodes": graph_result.get("nodes", []),
            "relationships": graph_result.get("relationships", []),
            "evidence_gaps": graph_result.get("evidence_gaps", []),
        }
        if not self.api_key:
            return {"mode": "deterministic_fallback", "summary": self._fallback(context), "model": None}
        payload = {
            "model": self.model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": "You are a cautious cybersecurity analyst. Use only the supplied graph context. Do not invent facts, CVEs, exploitability, sources, or relationships. Distinguish observed graph facts from hypotheses. If evidence is missing, state that explicitly. Return concise JSON with keys summary, supported_observations, hypotheses, evidence_gaps, next_safe_checks."},
                {"role": "user", "content": "Investigation query: " + query + "\nRetrieved graph context JSON:\n" + json.dumps(context, ensure_ascii=False)[:24000]},
            ],
            "response_format": {"type": "json_object"},
        }
        request = Request(self.endpoint, data=json.dumps(payload).encode("utf-8"), headers={"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            return {"mode": "llm_grounded", "model": self.model, **parsed}
        except (HTTPError, URLError, TimeoutError, KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
            return {"mode": "deterministic_fallback", "summary": self._fallback(context), "model": None, "provider_error": type(exc).__name__}

    @staticmethod
    def _fallback(context: dict) -> str:
        count = len(context.get("nodes", []))
        relationships = len(context.get("relationships", []))
        gaps = len(context.get("evidence_gaps", []))
        if not count:
            return "No matching verified graph context was found. Ingest trusted sources or explicitly inspect unverified leads."
        return f"Retrieved {count} graph entities and {relationships} relationships. {gaps} entities lack a source URL. This is a graph retrieval result, not proof of exploitability; verify each claim against authoritative evidence."
