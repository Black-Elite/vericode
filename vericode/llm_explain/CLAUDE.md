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

## How it works

1. `ollama pull qwen2.5-coder:1.5b` (done by `setup.sh`). It runs on a laptop
   with no GPU: in our benchmark it got 6 of 7 verdicts right at ~8-15s per
   finding. 3B and 7B are used if 1.5B isn't pulled, or via `VERICODE_MODEL`.
2. `evidence.py` (no AI) works out a one-line fact about the flagged line:
   what reaches a dangerous call (command-line input, a web request, a value
   the program generates, a fixed command) or whether a secret looks like a
   placeholder. It also decides whether the AI is allowed to clear the finding.
3. The prompt starts with fixed instructions and 3 short example answers, then
   the finding: the scanner's message, that fact, and 3 lines either side, with
   secrets redacted. Fixed text first lets Ollama reuse its work between
   findings; the examples are what made the 1.5B model write fixes as code. Ollama is given a JSON schema so the answer is always
   `{"reason", "is_real_risk", "fix"}` **in that order**: with the verdict
   first, small models answered before reasoning and contradicted themselves.
4. Safety rule: a "false alarm" verdict lowers the finding to low **only if
   the evidence agrees**. Otherwise it keeps blocking, with the AI's reason
   shown as a note. Real-looking secrets and fake imports are never cleared.
5. Public function: `enrich(findings: list[Finding]) -> list[Finding]`. Only
   findings already flagged by Layer 2 go to the model. Import findings are
   skipped: the AI may never clear them, and Layer 1's "Did you mean" is a
   better fix than the model's.

## Settings (environment variables)

| Variable | Default | Use |
|---|---|---|
| `VERICODE_MODEL` | first pulled of `qwen2.5-coder:1.5b`, `:3b`, `:7b` | Pick a model without editing code |
| `VERICODE_TIMEOUT` | `30` seconds | 1.5B took 11-20s per finding on a CPU-only laptop |
| `VERICODE_MAX_AI_FINDINGS` | `3` | Only the most severe findings go to the AI, to keep commits fast. The rest keep `is_real_risk=None`, so the gate still treats them as real |

## Tests

- `uv run pytest tests/test_llm_explain.py tests/test_evidence.py`: unit tests with faked AI replies. No model needed.
- `uv run pytest -m live -s -v`: runs against the real local model (skips if Ollama isn't running). Run it again with wifi off; it must still pass.

## Consistency add-on

If the codebase consistency check ships, it puts its evidence in the Finding's
`message` (e.g. "4 of 5 similar handlers raise ForbiddenError before deleting;
this one doesn't"). The prompt already includes `message`, so no change is needed here.

## Done when

- Given a sample Finding, returns a verdict, reason and fix within the timeout on a CPU-only laptop.
- Confirmed working with the network/wifi off.
- `uv run pytest -m live` passes on the presentation laptop, with and without wifi.

## Gotchas

- LLMs don't always return clean JSON — add a regex/try-except fallback that
  treats raw text as the explanation if parsing fails, so a malformed
  response never crashes the hook.
- Hard timeout per call (30s by default) with a graceful fallback message — a
  hang here would kill the live demo.
- The 1.5B model calls placeholder secrets ("changeme") real risks. Safe
  direction (the commit is blocked), but noisy.
- A fix can parse as code without fixing anything: for `eval(input())` it
  returned the same line. Treat the AI's fix as a suggestion.
- In the gate's report, render the same finding two ways: the flat
  static-rule message, and this layer's explanation/fix, side by side. That
  comparison is what proves to judges the LLM is doing real reasoning, not
  templating.
