# Git Hook, CLI & Commit Gate

Owner: Person A · Integration layer — the only module allowed to import the
other three.

## Goal

Wire `import_check`, `security_scan`, and `llm_explain` into one pre-commit
hook with a clear terminal report and a block/override gate.

## Build steps

1. Get staged files: `git diff --cached --name-only --diff-filter=ACM`.
2. Use the `pre-commit` framework (`.pre-commit-config.yaml` at repo root)
   rather than raw `.git/hooks`.
3. Call `import_check.run(staged_files)` → `security_scan.run(staged_files)`
   → collect all Findings → send high/medium ones to
   `llm_explain.enrich(findings)` → merge back.
4. Render with Rich: a table per file — line, severity, message, explanation,
   suggested/fixed code.
5. Gate logic: any `high` severity Finding → exit code 1, unless
   `VERICODE_OVERRIDE=1` or an interactive confirm is accepted. Log every
   override clearly.
6. Track and log total hook runtime.

## Done when

- `git commit` on a dirty test repo blocks with a readable report.
- `git commit` on a clean repo passes silently and fast.
- Override path works and is clearly logged.

## Interfaces — don't break these

This module imports `import_check.run()`, `security_scan.run()`, and
`llm_explain.enrich()` directly, and depends on `vericode.shared.finding.Finding`
staying the same shape. If any of those three change their signature, tell
the team immediately — this is the one place someone else's change can break
your work.
