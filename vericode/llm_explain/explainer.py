"""Layer 3: the required local-AI component. Triages false positives,
explains flagged findings in plain English, and writes corrected code — all
via a local Ollama model. See CLAUDE.md in this folder for the full spec.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

import ollama

from vericode.shared.finding import Finding

PRIMARY_MODEL = "qwen2.5-coder:7b"
FALLBACK_MODEL = "qwen2.5-coder:3b"
TIMEOUT_SECONDS = 10.0
MAX_AI_FINDINGS = 3
KEEP_ALIVE = "30m"
CONTEXT_LINES = 5
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}

PROMPT_TEMPLATE = """You are a code security reviewer. A static check flagged this issue:
Issue: {message}
File: {file}, Line: {line}
Code (with surrounding context):
{code_context}

Decide if this is a real risk given the context, or a false positive. Then explain why in 2-3 plain-English sentences, and write the corrected code (not just advice).
Secret values in the code are replaced with {redacted}; never invent or repeat secret values, load them from environment variables in the fix.
Respond as JSON: {{"is_real_risk": bool, "risk_reasoning": str, "explanation": str, "fixed_code": str}}"""

_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)

REDACTED = "<REDACTED>"
# Well-known token shapes, redacted wherever they appear.
_TOKEN_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{8,}"),            # Slack
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                      # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),               # GitHub
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),                    # OpenAI-style
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"),                   # Google API key
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{16,}"),   # auth headers
]
# name = "value" where the name looks secret-ish: keep the name, blank the value.
_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    ([\w.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|auth|credential|private[_-]?key)[\w.-]*
    ["']?\s*[:=]\s*)
    (["'])([^"'\n]{4,})\2
    """
)


def redact(text: str) -> str:
    """Blank secret values so they never reach the model or the report."""
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(
            lambda m: (m.group(1) + REDACTED) if m.groups() else REDACTED, text
        )

    def blank(m: re.Match) -> str:
        if m.group(3) == REDACTED:
            return m.group(0)
        return f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(2)}"

    return _SECRET_ASSIGNMENT.sub(blank, text)


def build_code_context(file: str, line: int, radius: int = CONTEXT_LINES) -> str:
    """Flagged line plus `radius` lines either side, numbered, marked with '>'.
    Returns a placeholder if the file can't be read."""
    try:
        lines = Path(file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "(source unavailable)"
    start = max(line - 1 - radius, 0)
    end = min(line + radius, len(lines))
    return "\n".join(
        f"{'>' if i + 1 == line else ' '} {i + 1}: {lines[i]}" for i in range(start, end)
    )


def _env_number(name: str, default: float, cast=float):
    try:
        value = cast(os.environ.get(name, default))
    except ValueError:
        return default
    return value if value > 0 else default


def timeout_seconds() -> float:
    """VERICODE_TIMEOUT override; CPU-only laptops need more than the default."""
    return _env_number("VERICODE_TIMEOUT", TIMEOUT_SECONDS)


def max_ai_findings() -> int:
    """VERICODE_MAX_AI_FINDINGS override; caps LLM calls per commit."""
    return _env_number("VERICODE_MAX_AI_FINDINGS", MAX_AI_FINDINGS, int)


def _client() -> ollama.Client:
    return ollama.Client(timeout=timeout_seconds())


@lru_cache(maxsize=1)
def pick_model() -> str:
    """VERICODE_MODEL override, else 7b, else 3b if only that is pulled.
    Raises RuntimeError when no usable model is installed."""
    override = os.environ.get("VERICODE_MODEL")
    if override:
        return override
    installed = {m.model for m in _client().list().models}
    for name in (PRIMARY_MODEL, FALLBACK_MODEL):
        if name in installed:
            return name
    raise RuntimeError(
        f"no model installed; run `ollama pull {PRIMARY_MODEL}` (or {FALLBACK_MODEL})"
    )


def _chat(prompt: str) -> str:
    """Single local LLM call. Isolated so tests can mock it."""
    response = _client().chat(
        model=pick_model(),
        messages=[{"role": "user", "content": prompt}],
        format="json",
        # otherwise ollama unloads the model after ~5 min idle and the next
        # commit waits for a multi-GB reload
        keep_alive=os.environ.get("VERICODE_KEEP_ALIVE", KEEP_ALIVE),
        options={"temperature": 0},
    )
    return response.message.content or ""


def _as_bool(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes"):
            return True
        if v in ("false", "no"):
            return False
    return None


def parse_response(raw: str) -> dict:
    """Parse model output into the four fields. Falls back to treating raw
    text as the explanation (is_real_risk=None) when JSON is unusable."""
    data = None
    for candidate in (raw, (_JSON_OBJECT.search(raw) or [None])[0] if raw else None):
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            data = parsed
            break

    if data is None:
        text = raw.strip()
        return {
            "is_real_risk": None,
            "risk_reasoning": None,
            "explanation": text or "LLM returned an empty response.",
            "fixed_code": None,
        }

    def text_or_none(key: str) -> str | None:
        v = data.get(key)
        return None if v is None else str(v)

    return {
        "is_real_risk": _as_bool(data.get("is_real_risk")),
        "risk_reasoning": text_or_none("risk_reasoning"),
        "explanation": text_or_none("explanation"),
        "fixed_code": text_or_none("fixed_code"),
    }


def _enrich_one(finding: Finding) -> None:
    prompt = PROMPT_TEMPLATE.format(
        message=redact(finding.message),
        file=finding.file,
        line=finding.line,
        code_context=redact(build_code_context(finding.file, finding.line)),
        redacted=REDACTED,
    )
    try:
        fields = parse_response(_chat(prompt))
    except Exception as exc:  # timeout, connection refused, missing model, ...
        finding.explanation = f"LLM unavailable, showing static check only ({type(exc).__name__}: {exc})"
        return

    # Redact again on the way out: the model may echo or hallucinate a secret.
    clean = {k: (redact(v) if isinstance(v, str) else v) for k, v in fields.items()}
    finding.is_real_risk = clean["is_real_risk"]
    finding.risk_reasoning = clean["risk_reasoning"]
    finding.explanation = clean["explanation"]
    finding.fixed_code = clean["fixed_code"]
    # Layer 1's "Did you mean X?" beats a model-written import fix; keep it visible.
    if finding.layer == "import_check" and finding.suggested_fix:
        finding.fixed_code = None
    if finding.is_real_risk is False:
        finding.severity = "low"


def enrich(findings: list[Finding]) -> list[Finding]:
    """Call the local LLM only on the given (already-flagged) findings, fill
    in is_real_risk / risk_reasoning / explanation / fixed_code, and
    downgrade severity when is_real_risk is False instead of dropping it.
    Never raises: on LLM failure the finding is left as-is with a note in
    `explanation` (is_real_risk stays None so the gate still treats it as real).

    Only the most severe max_ai_findings() findings go to the LLM, to keep
    the commit fast; the rest keep is_real_risk=None, so the gate still
    treats them as real. Returned in the original order.
    """
    ranked = sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity, len(SEVERITY_RANK)))
    limit = max_ai_findings()
    for finding in ranked[:limit]:
        _enrich_one(finding)
    for finding in ranked[limit:]:
        finding.explanation = (
            f"Not reviewed by the local AI (limit of {limit} per commit; "
            f"set VERICODE_MAX_AI_FINDINGS to raise it)."
        )
    return findings
