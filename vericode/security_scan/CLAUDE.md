# Layer 2 — Security Risk Scanner

Owner: Person B or C · No custom AI, wraps Semgrep. You own this folder only.

## Goal

Flag hardcoded secrets, injection risks, and unsafe `eval`/`exec`/shell use,
using Semgrep's offline rulesets.

## Build steps

1. `pip install semgrep`.
2. During setup (`setup.sh`, needs internet once): cache
   `semgrep --config p/secrets --config p/python` rulesets locally. Confirm a
   re-run works with networking disabled.
3. Wrap the CLI: `semgrep scan --config <cached-path> --json <staged files>`,
   scoped to staged files only.
4. Parse Semgrep's JSON output into `Finding` objects (import from
   `vericode.shared.finding`), mapping Semgrep severities to high/medium/low.
5. Return `list[Finding]`.

## Done when

- A test file with a hardcoded API key string and an `os.system(user_input)`
  call produces two Findings.
- Confirmed working with networking disabled.

## Gotchas

- Semgrep has ~1-2s startup overhead — fine for commit-time, mention it if
  asked about speed.
- Always scope `--include` to the staged file list, not the whole repo.
