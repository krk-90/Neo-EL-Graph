"""Deterministic safety controls for the Neo-EL-Graph RAG boundary.

Defense-in-depth only: these checks do not make prompt injection impossible.
Authorization must be enforced by trusted application code, never model output.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Iterable

@dataclass(frozen=True)
class GuardrailConfig:
    max_query_chars: int = 8_000
    max_context_chars: int = 40_000
    max_output_chars: int = 12_000
    block_obvious_injection: bool = True
    redact_pii: bool = True

@dataclass
class GuardrailResult:
    allowed: bool
    text: str
    reason: str | None = None
    risk_flags: list[str] = field(default_factory=list)

_INJECTION_PATTERNS = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"(reveal|print|show|repeat)\s+(the\s+)?(system|developer)\s+prompt", re.I),
    re.compile(r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|jailbroken)", re.I),
    re.compile(r"you\s+are\s+now\s+(dan|in\s+developer\s+mode)", re.I),
    re.compile(r"<\s*/?\s*(system|developer|assistant)\s*>", re.I),
    re.compile(r"\bDAN\s+mode\b", re.I),
)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
_SECRET = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,})\b")

def detect_prompt_injection(text: str) -> list[str]:
    if not isinstance(text, str):
        return ["non_string_input"]
    flags = [f"injection_pattern_{i + 1}" for i, pattern in enumerate(_INJECTION_PATTERNS) if pattern.search(text)]
    if re.search(r"(?i)\b(ignore|override|bypass)\b.{0,80}\b(safety|guardrails|instructions|policy)\b", text):
        flags.append("instruction_override")
    return flags

def validate_query(query: str, config: GuardrailConfig | None = None) -> GuardrailResult:
    config = config or GuardrailConfig()
    if not isinstance(query, str):
        return GuardrailResult(False, "", "query_must_be_text")
    cleaned = query.strip()
    if not cleaned:
        return GuardrailResult(False, "", "empty_query")
    if len(cleaned) > config.max_query_chars:
        return GuardrailResult(False, "", "query_too_long")
    flags = detect_prompt_injection(cleaned)
    if flags and config.block_obvious_injection:
        return GuardrailResult(False, "", "possible_prompt_injection", flags)
    return GuardrailResult(True, cleaned, risk_flags=flags)

def mark_untrusted_context(documents: Iterable[str], config: GuardrailConfig | None = None) -> GuardrailResult:
    config = config or GuardrailConfig()
    safe_docs = []
    total = 0
    for index, document in enumerate(documents, start=1):
        if not isinstance(document, str):
            continue
        remaining = config.max_context_chars - total
        if remaining <= 0:
            break
        clipped = document[:remaining]
        safe_docs.append(f'<untrusted_evidence index="{index}">\n{clipped}\n</untrusted_evidence>')
        total += len(clipped)
    return GuardrailResult(True, "\n\n".join(safe_docs), risk_flags=["retrieved_content_is_untrusted"])

def redact_sensitive_output(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = _EMAIL.sub("[REDACTED_EMAIL]", text)
    text = _SECRET.sub("[REDACTED_SECRET]", text)
    return _PHONE.sub("[REDACTED_PHONE]", text)

def validate_output(output: str, config: GuardrailConfig | None = None) -> GuardrailResult:
    config = config or GuardrailConfig()
    if not isinstance(output, str):
        return GuardrailResult(False, "", "output_must_be_text")
    cleaned = output.strip()
    if not cleaned:
        return GuardrailResult(False, "", "empty_model_output")
    if len(cleaned) > config.max_output_chars:
        return GuardrailResult(False, "", "output_too_long")
    flags = []
    if config.redact_pii:
        redacted = redact_sensitive_output(cleaned)
        if redacted != cleaned:
            flags.append("sensitive_data_redacted")
        cleaned = redacted
    return GuardrailResult(True, cleaned, risk_flags=flags)

def safe_fallback(reason: str = "I could not safely complete that request.") -> str:
    return reason
