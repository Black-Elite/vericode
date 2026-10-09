# Layer 2 — Security Risk Scanner

Owner: Person B or C · No custom AI, wraps Semgrep. You own this folder only.

## Goal

Flag hardcoded secrets, injection risks, and unsafe `eval`/`exec`/shell use,
offline.

Three scanners, in order of cost:

- **betterleaks** (`pybetterleaks`) — secrets. ~9ms/file.
- **stdlib `ast`** — `eval`, `exec`, `os.system`, `subprocess(shell=True)`.
  Sub-millisecond. A literal argument is `medium`, anything else is `high`.
- **Semgrep** — the remaining 134 rules. **Opt-in via `VERICODE_SEMGREP=1`**,
  because it costs ~3s per run against ~50ms for the other two, and ~1.8s of
  that is a fixed floor no amount of rule pruning gets under.

Findings are deduped on `(file, line)`; betterleaks wins, then ast, then semgrep.

## Build steps

1. `pip install semgrep`.
2. During setup (`setup.sh`, needs internet once):
   `scripts/build_semgrep_rules.py` downloads the rulesets and merges them into
   one `data/rules.yml`. `--dryrun` caches nothing, hence the download. Rules for
   languages we never scan are dropped (279 → 134) because semgrep parses every
   rule on every run, and that parsing is most of the hook's runtime.
   `p/python` is not used — its injection rules only fire on django/flask taint
   sources and miss plain `eval` / `os.system`; it's replaced by
   `p/security-audit` plus the `dangerous-system-call` rule.
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
- Semgrep exits 1 when it finds something, so `check=True` is wrong.
- Betterleaks runs via `pybetterleaks` (wheels, no binary to install). Its line
  numbers start at 0 *and* the 0 is omitted, so `(line or 0) + 1`. Always pass
  `validation=False` — validation uploads the secret to vendor APIs.
- Secret values never enter a `Finding`. `leak.secret` and semgrep's
  `extra["lines"]` both hold raw credentials; `file:line` is enough.
