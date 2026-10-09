"""Layer 3: the required local-AI component. Triages false positives,
explains flagged findings in plain English, and writes corrected code — all
via a local Ollama model. See CLAUDE.md in this folder for the full spec.
"""

from __future__ import annotations

from vericode.shared.finding import Finding

PROMPT_TEMPLATE = """You are a code security reviewer. A static check flagged this issue:
Issue: {message}
File: {file}, Line: {line}
Code (with surrounding context):
{code_context}

Decide if this is a real risk given the context, or a false positive. Then explain why in 2-3 plain-English sentences, and write the corrected code (not just advice).
Respond as JSON: {{"is_real_risk": bool, "risk_reasoning": str, "explanation": str, "fixed_code": str}}"""


def enrich(findings: list[Finding]) -> list[Finding]:
    """Call the local LLM only on the given (already-flagged) findings, fill
    in is_real_risk / risk_reasoning / explanation / fixed_code, and
    downgrade severity when is_real_risk is False instead of dropping it.
    """
    for finding in findings:
        pass
        # TODO: build code_context from surrounding lines, call Ollama's
        # local HTTP API, parse JSON response with a fallback for malformed
        # output, merge fields into `finding`, downgrade severity if the
        # LLM says this isn't a real risk.
    return findings
