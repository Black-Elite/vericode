"""Layer 4: the pre-commit entrypoint. Calls layers 1-3 in order, renders a
report, and decides whether to block the commit. See CLAUDE.md in this
folder for the full spec.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from vericode.gate.ui import header, override_hint, render_error, robot_banner, use_ascii
from vericode.import_check.checker import run as run_import_check
from vericode.llm_explain.explainer import enrich
from vericode.security_scan.scanner import run as run_security_scan
from vericode.shared.finding import Finding

SEVERITY_STYLE = {"high": "bold red", "medium": "yellow", "low": "dim"}
LAYER_LABEL = {"import_check": "import", "security_scan": "security", "llm_explain": "ai"}
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_PATCH_LINE_LIMIT = 12


def _console() -> Console:
    """Markup stays on so severity colors work. Created after use_ascii()."""
    return Console(highlight=False)


def _git_text(args: list[str]) -> str:
    out = subprocess.run(
        args,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return out.stdout or ""


def get_staged_files() -> list[str]:
    text = _git_text(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"])
    return [line for line in text.splitlines() if line]


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
    text = _git_text(["git", "diff", "--cached", "-U0", "--diff-filter=ACM"])
    return parse_added_lines(text)


def _row_table(ascii_mode: bool, show_header: bool) -> Table:
    table = Table(
        box=box.ASCII if ascii_mode else box.SIMPLE_HEAD,
        pad_edge=False,
        show_edge=False,
        show_header=show_header,
        expand=False,
    )
    table.add_column("Line", justify="right", style="cyan", no_wrap=True, min_width=4)
    table.add_column("Severity", no_wrap=True, min_width=9)
    table.add_column("Check", style="dim", no_wrap=True, min_width=8)
    return table


_AI_VERDICT = {True: ("real risk", "bold red"), False: ("false alarm", "green")}


def _row_ai(finding: Finding) -> str | None:
    """AI text that belongs on this row. Skip-notes stay in the footer."""
    if finding.is_real_risk is None:
        return finding.risk_reasoning or None
    return finding.explanation or finding.risk_reasoning or None


def _print_patch(console: Console, fixed_code: str) -> None:
    lines = fixed_code.splitlines() or [""]
    for line in lines[:_PATCH_LINE_LIMIT]:
        console.print(Padding(Text(line, style="green"), (0, 0, 0, 4)))
    if len(lines) > _PATCH_LINE_LIMIT:
        console.print(Padding(Text("... (truncated)", style="dim"), (0, 0, 0, 4)))


def _print_details(console: Console, finding: Finding) -> None:
    """Issue, optional Local AI, and Fix, indented to the full console width."""
    if finding.message:
        console.print(Padding(Text(finding.message), (0, 0, 0, 2)))
    ai_text = _row_ai(finding)
    if ai_text:
        ai = Text()
        ai.append("Local AI", style="dim")
        verdict = _AI_VERDICT.get(finding.is_real_risk)
        if verdict:
            ai.append(f" ({verdict[0]})", style=verdict[1])
        ai.append(": ", style="dim")
        ai.append(ai_text)
        console.print(Padding(ai, (0, 0, 0, 2)))
    if finding.is_real_risk is False:
        # a cleared finding needs no fix; the scanner's generic advice would contradict the verdict
        console.print(Padding(Text("Fix: none needed", style="dim"), (0, 0, 0, 2)))
        return
    suggested = finding.suggested_fix or ""
    patch = finding.fixed_code or ""
    if not suggested and not patch:
        return
    fix = Text("Fix:", style="dim")
    if suggested:
        fix.append(" ")
        fix.append(suggested)
    console.print(Padding(fix, (0, 0, 0, 2)))
    if patch:
        _print_patch(console, patch)


def render_report(findings: list[Finding], ascii_mode: bool = False) -> None:
    console = _console()

    for file in dict.fromkeys(f.file for f in findings):
        console.print(f"\n[bold underline]{escape(file)}[/]")
        rows = [item for item in findings if item.file == file]
        rows.sort(key=lambda item: (_SEVERITY_RANK.get(item.severity, 9), item.line))
        for index, finding in enumerate(rows):
            table = _row_table(ascii_mode, show_header=index == 0)
            severity = f"[{SEVERITY_STYLE.get(finding.severity, '')}]{finding.severity}[/]"
            if finding.is_real_risk is False:
                severity += "\n[dim]dismissed[/]"
            table.add_row(
                str(finding.line),
                severity,
                LAYER_LABEL.get(finding.layer, finding.layer),
            )
            console.print(table)
            _print_details(console, finding)

    skipped = {
        finding.explanation
        for finding in findings
        if finding.is_real_risk is None and finding.explanation
    }
    for note in sorted(note for note in skipped if note):
        console.print(f"[dim]{escape(note)}[/]")


def _missing_file_message(exc: FileNotFoundError) -> tuple[str, str]:
    text = f"{exc.filename or ''} {exc}"
    if "pypi_all.txt" in text or "pypi_top.txt" in text:
        return "Offline package list not found.", "Run ./setup.sh while online first."
    name = exc.filename or str(exc)
    return f"File not found: {name}", ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vericode")
    parser.add_argument("--ascii", action="store_true")
    parser.add_argument("--banner", action="store_true")
    args, _unknown = parser.parse_known_args(argv)
    # Before the banner, the report, and the header. Nothing has been printed yet.
    ascii_mode = use_ascii(args.ascii)

    started = time.perf_counter()
    try:
        staged = get_staged_files()
        added = added_lines()
    except subprocess.CalledProcessError:
        render_error(
            "Not a git repository or git failed.",
            "Run Vericode from inside a git repository.",
            ascii_mode,
        )
        return 2

    try:
        findings = run_import_check(staged) + run_security_scan(staged)
        findings = [finding for finding in findings if finding.line in added.get(finding.file, ())]
        enrich([finding for finding in findings if finding.severity in ("high", "medium")])
    except FileNotFoundError as exc:
        title, body = _missing_file_message(exc)
        render_error(title, body, ascii_mode)
        return 2

    blocking = [
        finding
        for finding in findings
        if finding.severity == "high" and finding.is_real_risk is not False
    ]
    override = bool(blocking) and os.environ.get("VERICODE_OVERRIDE") == "1"
    blocked = bool(blocking) and not override

    if args.banner or blocked:
        robot_banner(ascii_mode, "blocked" if blocked else "idle")
    if findings:
        render_report(findings, ascii_mode)

    elapsed = time.perf_counter() - started
    if blocked:
        status = "blocked"
    elif findings:
        status = "warning"
    else:
        status = "passed"
    header(status, ascii_mode)
    _console().print(
        f"[dim]Vericode: {len(staged)} staged file(s), "
        f"{len(findings)} finding(s), {elapsed:.1f}s[/dim]"
    )

    if not blocking:
        return 0
    if override:
        _console().print(
            f"[bold yellow]OVERRIDE: committing past {len(blocking)} high-severity "
            f"issue(s) because VERICODE_OVERRIDE=1.[/bold yellow]"
        )
        return 0

    _console().print(
        f"[bold red]Blocked: {len(blocking)} high-severity issue(s).[/bold red] "
        f"Fix them, or commit anyway with {escape(override_hint())}"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
