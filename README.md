# Vericode

> "AI writes code that doesn't exist. Vericode catches it before it ships."

Offline AI code verification — a Git pre-commit hook that uses a local LLM to
catch hallucinated imports, insecure code, and false-positive noise in staged
changes. No cloud, no uploads: source code never leaves your laptop.

Built for **AppBuildersPH Hackathon 2026** (theme: Local AI).

## Why local AI

Cloud code reviewers require uploading private source code. Static linters
can't judge whether an API call actually exists, or explain *why* something
is risky in plain language — that needs an LLM, and it has to run locally or
the tool defeats its own trust model. See `is_real_risk` / `risk_reasoning` /
`explanation` / `fixed_code` in [`vericode/llm_explain/`](vericode/llm_explain/)
for where that reasoning happens.

## Architecture

```
staged files
   │
   ├─► vericode/import_check   (fast, no AI — flags hallucinated packages)
   ├─► vericode/security_scan  (Semgrep, offline rulesets)
   │
   ▼
vericode/llm_explain  (local LLM — triages false positives, explains, fixes)
   │
   ▼
vericode/gate  (renders report, blocks or allows the commit)
```

Each layer is independently buildable — see the `CLAUDE.md` in each
`vericode/<layer>/` folder for that module's spec and "done when" checklist.

## Setup

```bash
./setup.sh      # one-time: pulls the Ollama model, caches Semgrep rules, builds the package snapshot
pre-commit install
```

## Usage

Just commit normally:

```bash
git add .
git commit -m "..."
```

Vericode runs automatically. A blocked commit can be forced through with
`VERICODE_OVERRIDE=1 git commit ...` after reviewing the report.

## What runs locally vs. what needs internet

Everything runs locally at commit time — import checking, security scanning,
and LLM inference. Internet is only used once, during `setup.sh`, to download
the model, cache Semgrep's rulesets, and build the offline package snapshot.

## Disclosures

- Model: Qwen2.5-Coder-7B (Q4_K_M), via Ollama
- Security rules: Semgrep (`p/secrets`, `p/python`)
- Parsing: Python `ast`, `importlib`, `sys.stdlib_module_names`
- Report rendering: Rich
- Hook framework: `pre-commit`

## Development

```bash
pip install -r requirements.txt
pytest tests/
```
