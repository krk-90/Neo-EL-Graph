# RAG security boundary

This package is independent of the current RAG chain and is intended for later orchestrator integration.

## Integration contract

1. Call validate_query(query) before retrieval/model invocation. Reject when allowed is false.
2. After retrieval, call mark_untrusted_context([doc.page_content, ...]). Pass its bounded text into the human/context message, never a system message.
3. Use SYSTEM_PROMPT, DEVELOPER_PROMPT and HUMAN_PROMPT_TEMPLATE as separate role layers where supported.
4. Validate generated text with validate_output(answer). On rejection, return safe_fallback() and log only a safe reason code.
5. Enforce authentication, authorization, tenant boundaries, tool permissions, rate limits and secret access in trusted application code.

## Limitations

Pattern matching catches only a subset of obvious injection attempts. It cannot prove a model is prompt-injection-proof. Combine it with least-privilege tools, strict schemas, retrieval source controls, output validation, adversarial tests, monitoring and human review for high-impact actions.

PII patterns are basic accidental-disclosure filters, not comprehensive DLP. Never log raw prompts, credentials or sensitive retrieved content by default.


## API and operational controls for the orchestrator

- Authenticate callers before invoking this package; authorize each operation using server-side identity and scopes.
- Apply request-body and query-size limits, rate limits, timeouts, and concurrency limits at the API boundary.
- Keep CORS origins explicit; do not use wildcard origins with credentialed requests.
- Keep provider keys in environment/secret storage; never return them or place them in prompts.
- Restrict model tools to an explicit allowlist and least privilege. Retrieval must not grant tool permissions.
- Keep bounded provider retries for transient failures only; avoid retrying validation, authorization, or policy denials.
- Log stable reason codes, latency and token counts; do not log raw sensitive content.
- Return the fixed safe fallback for unexpected model/runtime failures. Preserve detailed exceptions only in access-controlled diagnostics after redaction.
- Set provider timeouts and a maximum output token budget to prevent unbounded work.
