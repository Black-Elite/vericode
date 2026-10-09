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
   Findings are filtered to lines this commit actually adds (`added_lines()`,
   from `git diff --cached -U0`), so nobody is blocked by a problem that was
   already in a file they merely touched. This applies to every layer.
   The layers read files from disk. That is the staged version when run by
   pre-commit, because pre-commit stashes unstaged edits before running hooks
   and restores them after (tested: a staged `os.system(sys.argv[1])` was
   blocked even though the copy on disk had been cleaned up but not staged).
   Running `python -m vericode.gate.cli` by hand checks the working copy.
4. Render with Rich: a table per file — line, severity, message, explanation,
   suggested/fixed code. The AI's verdict is shown in words ("Local AI (real
   risk)" / "Local AI (false alarm)"), and a finding the AI cleared shows
   "Fix: none needed" instead of the scanner's generic advice.
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
