# Vericode

Offline AI code verification — a Git pre-commit hook that catches hallucinated
imports, insecure code, and false-positive noise using a local LLM. No cloud,
no uploads. Built for AppBuildersPH Hackathon 2026 (theme: Local AI).

Full plan, timeline, and research backing: see the shared build-plan doc
(ask the team for the link, or check `docs/Vericode_Hackathon_Plan.md` if it's
been copied into this repo).

## Architecture

Four pieces, each independently buildable and testable:

1. `vericode/import_check/` — flags imports of packages that don't exist (no AI)
2. `vericode/security_scan/` — wraps Semgrep for hardcoded secrets / injection (no AI)
3. `vericode/llm_explain/` — the local LLM: triages false positives, explains, writes fixes
4. `vericode/gate/` — glues 1→2→3 together, renders the report, blocks/allows the commit

## The shared contract — do not break this

Every layer is a function with this signature:

```python
def run(staged_files: list[str]) -> list[Finding]:
    ...
```

`Finding` is defined once in `vericode/shared/finding.py`. Import it, don't
redefine it. If you need to change its shape, say so in the team chat first —
`vericode/gate/cli.py` imports all three layers directly and will break
silently otherwise.

## Tech stack

- Python 3.11+, managed with `uv` — not pip. Dependencies live in `pyproject.toml`
  / `uv.lock`. Don't add a `requirements.txt` or run bare `pip install`; use
  `uv add <package>` so the lockfile stays correct for everyone.
- Local LLM: Ollama, `qwen2.5-coder:7b` (fallback `qwen2.5-coder:3b` on slower hardware)
- Security rules: Semgrep (`p/secrets`, `p/python`), cached locally for offline use
- Parsing: stdlib `ast`, `importlib.util`, `sys.stdlib_module_names`
- Report rendering: Rich
- Hook framework: `pre-commit`

## Conventions

- Every layer's `run()` must work standalone against a dummy file list before
  it's wired into the gate — don't block on integration to test your own piece.
- The LLM layer (`llm_explain`) only ever processes findings already flagged
  by layers 1–2. Never run it over a whole diff or clean code — that's what
  keeps the hook fast enough to demo live.
- Nothing here should require internet at runtime. One-time setup downloads
  (model pull, PyPI snapshot, Semgrep ruleset cache) happen via `setup.sh`,
  before building starts.
- Keep functions small and testable; this is a hackathon build, skip
  speculative abstraction.

## Commands

```bash
./setup.sh                        # one-time: pulls model, builds package snapshot, caches semgrep rules
uv run pytest tests/              # run tests
uv run python -m vericode.gate.cli # run the gate manually against currently staged files
uv add <package>                   # add a new dependency (updates pyproject.toml + uv.lock)
```
