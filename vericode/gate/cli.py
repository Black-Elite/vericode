"""Layer 4: the pre-commit entrypoint. Calls layers 1-3 in order, renders a
report, and decides whether to block the commit. See CLAUDE.md in this
folder for the full spec.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

from rich.console import Console
from rich.table import Table

from vericode.import_check.checker import run as run_import_check
from vericode.security_scan.scanner import run as run_security_scan
from vericode.llm_explain.explainer import enrich
from vericode.shared.finding import Finding

console = Console(highlight=False)

SEVERITY_STYLE = {"high": "bold red", "medium": "yellow", "low": "dim"}


def get_staged_files() -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True, check=True,
    )
    return [line for line in out.stdout.splitlines() if line]


def parse_added_lines(diff: str) -> dict[str, set[int]]:
    """Line numbers added, per file, from `git diff -U0` hunk headers."""
    added: dict[str, set[int]] = {}
    current: set[int] | None = None
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = added.setdefault(line[6:], set())
        elif line.startswith("@@") and current is not None:
            # @@ -old,n +start,count @@
            start, _, count = line.split("+")[1].split(" ")[0].partition(",")
            current.update(range(int(start), int(start) + int(count or 1)))
    return added


def added_lines() -> dict[str, set[int]]:
    """Line numbers this commit actually adds, per file."""
    out = subprocess.run(
        ["git", "diff", "--cached", "-U0", "--diff-filter=ACM"],
        capture_output=True, text=True, check=True,
    )
    return parse_added_lines(out.stdout)


def render_report(findings: list[Finding]) -> None:
    for file in dict.fromkeys(f.file for f in findings):
        table = Table(title=file, title_justify="left", title_style="bold")
        table.add_column("Line", justify="right")
        table.add_column("Severity")
        table.add_column("Issue")
        table.add_column("Why", max_width=50)
        table.add_column("Suggested fix", max_width=40)
        for f in (x for x in findings if x.file == file):
            message = f.message
            if f.is_real_risk is False:
                message += "\n[dim](local AI: likely a false positive)[/dim]"
            table.add_row(
                str(f.line),
                f"[{SEVERITY_STYLE.get(f.severity, '')}]{f.severity}[/]",
                message,
                f.explanation or f.risk_reasoning or "",
                f.fixed_code or f.suggested_fix or "",
            )
        console.print(table)


def main() -> int:
    started = time.perf_counter()
    staged = get_staged_files()
    findings = run_import_check(staged) + run_security_scan(staged)

    # only judge what this commit adds, not what the file already contained
    added = added_lines()
    findings = [f for f in findings if f.line in added.get(f.file, ())]

    enrich([f for f in findings if f.severity in ("high", "medium")])

    if findings:
        render_report(findings)
    elapsed = time.perf_counter() - started
    console.print(
        f"[dim]Vericode: {len(staged)} staged file(s), "
        f"{len(findings)} finding(s), {elapsed:.1f}s[/dim]"
    )

    blocking = [f for f in findings if f.severity == "high" and f.is_real_risk is not False]
    if not blocking:
        return 0

    if os.environ.get("VERICODE_OVERRIDE") == "1":
        console.print(
            f"[bold yellow]OVERRIDE: committing past {len(blocking)} high-severity "
            f"issue(s) because VERICODE_OVERRIDE=1.[/bold yellow]"
        )
        return 0

    console.print(
        f"[bold red]Blocked: {len(blocking)} high-severity issue(s).[/bold red] "
        f"Fix them, or commit anyway with VERICODE_OVERRIDE=1 git commit ..."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
