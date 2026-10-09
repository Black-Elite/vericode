"""Layer 2: wraps Semgrep's offline rulesets for secrets/injection risks. No
custom AI. See CLAUDE.md in this folder for the full spec.
"""

from __future__ import annotations

from vericode.shared.finding import Finding


def run(staged_files: list[str]) -> list[Finding]:
    """Run semgrep --config <cached rules> --json against staged_files only,
    and map its output into Findings.
    """
    findings: list[Finding] = []
    # TODO: subprocess call to semgrep scan, parse JSON output.
    return findings
