"""Layer 4: the pre-commit entrypoint. Calls layers 1-3 in order, renders a
report, and decides whether to block the commit. See CLAUDE.md in this
folder for the full spec.
"""

from __future__ import annotations

import subprocess
import sys

from vericode.import_check.checker import run as run_import_check
from vericode.security_scan.scanner import run as run_security_scan
from vericode.llm_explain.explainer import enrich
from vericode.shared.finding import Finding


def get_staged_files() -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True, check=True,
    )
    return [line for line in out.stdout.splitlines() if line]


def render_report(findings: list[Finding]) -> None:
    # TODO: Rich table per file — line, severity, message, explanation, fixed_code.
    for f in findings:
        print(f"[{f.severity}] {f.file}:{f.line} {f.message}")
        if f.explanation:
            print(f"   why: {f.explanation}")
        if f.fixed_code:
            print(f"   fix: {f.fixed_code}")


def main() -> int:
    staged = get_staged_files()
    findings = run_import_check(staged) + run_security_scan(staged)

    to_enrich = [f for f in findings if f.severity in ("high", "medium")]
    enrich(to_enrich)

    render_report(findings)

    blocking = [f for f in findings if f.severity == "high" and f.is_real_risk is not False]
    if blocking:
        print(f"\nBlocked: {len(blocking)} high-severity issue(s). "
              f"Set VERICODE_OVERRIDE=1 to commit anyway.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
