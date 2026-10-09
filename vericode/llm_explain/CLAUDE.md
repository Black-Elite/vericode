# Layer 3 — Local LLM Explainer

Owner: Person C · This is the Required local-AI component — the whole
submission's "Local AI Implementation" score depends on this working. You own
this folder only.

## Goal

Take flagged findings from Layers 1-2, plus surrounding code context, and
produce three things a static rule cannot:

1. A verdict on whether the flagged line is a real risk in context
   (false-positive triage) — `is_real_risk` + `risk_reasoning`.
2. A plain-English explanation — `explanation`.
3. An actual corrected code snippet, not prose advice — `fixed_code`.

All running entirely on-device via Ollama.

## Build steps

1. `ollama pull qwen2.5-coder:7b` (Q4_K_M, ~4.5GB). Fallback
   `qwen2.5-coder:3b` if the demo machine is slow.
2. Prompt template — only pass the flagged line + a few lines of context,
   never the whole diff:

```
You are a code security reviewer. A static check flagged this issue:
Issue: {message}
File: {file}, Line: {line}
Code (with surrounding context):
{code_context}

Decide if this is a real risk given the context, or a false positive. Then
explain why in 2-3 plain-English sentences, and write the corrected code
(not just advice).
Respond as JSON: {"is_real_risk": bool, "risk_reasoning": str,
"explanation": str, "fixed_code": str}
```

3. Call via Ollama's local HTTP API (`http://localhost:11434/api/generate`)
   or the `ollama` Python package.
4. Parse the JSON, merge the four fields into the existing `Finding` (import
   from `vericode.shared.finding`). If `is_real_risk` is false, downgrade
   severity rather than dropping the Finding — the report should still show
   what the LLM dismissed and why.
5. Public function: `enrich(findings: list[Finding]) -> list[Finding]`. Only
   call the LLM on findings already flagged by Layer 1/2 — never run it over
   clean code.

## Done when

- Given a sample Finding, returns an explanation + fix within ~3-5 seconds.
- Confirmed working with the network/wifi off.

## Gotchas

- LLMs don't always return clean JSON — add a regex/try-except fallback that
  treats raw text as the explanation if parsing fails, so a malformed
  response never crashes the hook.
- Hard timeout per call (~10s) with a graceful fallback message — a hang
  here would kill the live demo.
- In the gate's report, render the same finding two ways: the flat
  static-rule message, and this layer's explanation/fix, side by side. That
  comparison is what proves to judges the LLM is doing real reasoning, not
  templating.
