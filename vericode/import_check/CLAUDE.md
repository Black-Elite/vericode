# Layer 1 — Hallucinated Import Detector

Owner: Person B · No AI, pure static analysis. You own this folder only —
nothing here should import from `security_scan`, `llm_explain`, or `gate`.

## Goal

Flag imports of Python packages that don't exist, before anything reaches the
LLM layer.

## Build steps

1. Parse staged files with `ast.walk` — handle `import x`, `from x import y`, aliasing.
2. Build (or load, from `setup.sh`'s output) an offline snapshot of the top
   ~15-20k PyPI package names as local JSON/SQLite.
3. For each imported top-level name, check in order: stdlib
   (`sys.stdlib_module_names`) → installed (`importlib.util.find_spec`) →
   offline snapshot. None of these hit → flag `high` severity.
4. Fuzzy-match the unknown name against the snapshot (`difflib.get_close_matches`)
   to suggest the likely correct package name, put it in `suggested_fix`.
5. Return `list[Finding]` — import `Finding` from `vericode.shared.finding`,
   don't redefine it.

## Done when

- A test file with a known-fake import (e.g. `import pandas_fast_reader`)
  produces a `high` severity Finding with a suggested fix.
- A clean file returns an empty list.
- Runs in under ~1 second on a typical diff.

## Gotchas

- Don't flag relative/local imports or this project's own modules — check
  against the project root and `sys.path` first.
- Always check stdlib before flagging.
