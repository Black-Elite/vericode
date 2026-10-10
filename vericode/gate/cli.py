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

from rich.console import Console
from rich.text import Text

from vericode.gate.ui import (
    console_options,
    display_text,
    friendly_unavailable,
    mask_quotes_for,
    render_error,
    render_next_steps,
    robot_banner,
    use_ascii,
    verdict_banner,
)
from vericode.consistency.checker import run as run_consistency
from vericode.import_check.checker import run as run_import_check
from vericode.llm_explain.explainer import LLM_UNAVAILABLE_PREFIX, enrich
from vericode.security_scan.scanner import run as run_security_scan
from vericode.shared.finding import Finding

SEVERITY_STYLE = {"high": "bold red", "medium": "yellow", "low": "dim"}
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_PATCH_LINE_LIMIT = 12
_SOURCE_LIMIT = 1_000_000
NOT_REVIEWED_PREFIX = "Not reviewed by the local AI"
_LAYER_CHIPS = (
    ("import_check", "imports"),
    ("security_scan", "security"),
    ("consistency", "patterns"),
)


def _console() -> Console:
    """Created after use_ascii(). Finding text is printed as Text, not markup."""
    return Console(highlight=False, **console_options())


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


def _live(findings: list[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.is_real_risk is not False]


def _dismissed(findings: list[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.is_real_risk is False]


def _offered_to_model(findings: list[Finding]) -> list[Finding]:
    """High and medium findings enrich() may send. Import findings are never sent."""
    return [
        finding
        for finding in findings
        if finding.severity in ("high", "medium") and finding.layer != "import_check"
    ]


def _model_answered(finding: Finding) -> bool:
    """True when enrich() recorded a model answer, not a skip or outage note.

    Scanners do not set explanation or is_real_risk. Only offered findings are
    counted, so a stray field on an import finding cannot inflate reviewed N.
    """
    if finding.is_real_risk is not None:
        return True
    text = finding.explanation or ""
    if not text:
        return False
    if text.startswith(LLM_UNAVAILABLE_PREFIX) or text.startswith(NOT_REVIEWED_PREFIX):
        return False
    return True


def _ai_chip(findings: list[Finding]) -> tuple[str, str]:
    offered = _offered_to_model(findings)
    answered = [finding for finding in offered if _model_answered(finding)]
    if answered:
        return "pass", f"reviewed {len(answered)}"
    if any((finding.explanation or "").startswith(LLM_UNAVAILABLE_PREFIX) for finding in offered):
        return "fail", "unavailable"
    if not offered:
        return "skip", "not needed"
    return "skip", "skipped"


def _icon(state: str, ascii_mode: bool) -> str:
    if ascii_mode:
        return {"pass": "[OK]", "fail": "[X]", "skip": "[-]"}[state]
    return {"pass": "✔", "fail": "✖", "skip": "[-]"}[state]


def _plain(text: str, ascii_mode: bool, finding: Finding | None = None) -> str:
    """Mask tokens always. mask_quotes_for decides whether long quotes are hidden."""
    return display_text(text, ascii_mode, mask_quotes=mask_quotes_for(finding))


def _cut(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[: max(width, 0)]
    return text[: width - 3] + "..."


def _sep(ascii_mode: bool) -> str:
    return " | " if ascii_mode else " \u00b7 "


def _count_text(findings: list[Finding], dismissed: int, ascii_mode: bool) -> str:
    parts = []
    labels = (("high", "must-fix"), ("medium", "warning"), ("low", "note(s)"))
    for severity, label in labels:
        count = sum(1 for finding in findings if finding.severity == severity)
        if count:
            parts.append(f"{count} {label}")
    if dismissed:
        parts.append(f"{dismissed} dismissed by local AI")
    return _sep(ascii_mode).join(parts)


def _summary_counts(
    status: str,
    live: list[Finding],
    findings: list[Finding],
    files: int,
    ascii_mode: bool,
) -> str:
    dismissed = len(_dismissed(findings))
    if status == "passed":
        noun = "file" if files == 1 else "files"
        text = f"{files} {noun} checked, no issues"
        if dismissed:
            return text + _sep(ascii_mode) + f"{dismissed} dismissed by local AI"
        return text
    return _count_text(live, dismissed, ascii_mode)


def print_checks(
    findings: list[Finding],
    timings: dict[str, float],
    ascii_mode: bool,
) -> None:
    """One strip: imports, security, patterns, and the local AI."""
    console = _console()
    live = _live(findings)
    parts = []
    for layer, label in _LAYER_CHIPS:
        failed = any(finding.layer == layer for finding in live)
        parts.append(
            f"{_icon('fail' if failed else 'pass', ascii_mode)} {label} {timings[layer]:.1f}s"
        )
    state, detail = _ai_chip(findings)
    parts.append(f"{_icon(state, ascii_mode)} AI {timings['ai']:.1f}s {detail}")
    console.print(Text(" ".join(parts)))


def _staged_lines(path: str, cache: dict[str, list[str] | None]) -> list[str] | None:
    if path in cache:
        return cache[path]
    cache[path] = None
    try:
        text = _git_text(["git", "show", f":{path}"])
    except subprocess.CalledProcessError:
        return None
    if "\x00" in text or len(text) > _SOURCE_LIMIT:
        return None
    lines = text.splitlines()
    cache[path] = lines
    return lines


def _print_frame(
    console: Console,
    finding: Finding,
    cache: dict[str, list[str] | None],
    ascii_mode: bool,
) -> str | None:
    """Staged line, plus neighbors. Returns the offending line when it was shown."""
    lines = _staged_lines(finding.file, cache)
    if lines is None or finding.line < 1 or finding.line > len(lines):
        return None
    width = console.width or 80
    for index in (finding.line - 2, finding.line - 1, finding.line):
        if index < 0 or index >= len(lines):
            continue
        number = index + 1
        current = number == finding.line
        prefix = f"{'>' if current else ' '} {number:>4} | "
        owner = finding if current else None
        source = _cut(_plain(lines[index], ascii_mode, owner), max(width - len(prefix), 0))
        text = Text()
        text.append(prefix, style="bold cyan" if current else "dim")
        text.append(source)
        console.print(text)
    return lines[finding.line - 1]


def _print_heading(console: Console, finding: Finding, ascii_mode: bool) -> None:
    width = console.width or 80
    severity = finding.severity.upper()
    loc = _plain(f"{finding.file}:{finding.line}", ascii_mode)
    message = _plain(finding.message, ascii_mode, finding)
    first = ""
    if message:
        first = message.splitlines()[0]
    room = width - len(f"{severity}  {loc}  ")
    title = _cut(first, room) if room > 0 else ""
    line = Text()
    line.append(f"{severity}  ", style=SEVERITY_STYLE.get(finding.severity, ""))
    line.append(loc, style="bold")
    if title:
        line.append("  ")
        line.append(title)
    console.print(line)
    if message and (title != first or "\n" in message):
        console.print(Text(message))


def _ai_text(finding: Finding) -> str | None:
    text = finding.explanation or finding.risk_reasoning
    if not text:
        return None
    if text.startswith(LLM_UNAVAILABLE_PREFIX) or text.startswith(NOT_REVIEWED_PREFIX):
        return None
    return text


def _print_fix(console: Console, finding: Finding, source_line: str | None, ascii_mode: bool) -> None:
    patch = _plain(finding.fixed_code or "", ascii_mode, finding)
    if patch:
        plus = patch.splitlines() or [""]
        console.print(Text("Suggested fix:", style="dim"))
        if len(plus) == 1 and source_line is not None:
            console.print(Text("- " + _plain(source_line, ascii_mode, finding), style="red"))
        for line in plus[:_PATCH_LINE_LIMIT]:
            console.print(Text("+ " + line, style="green"))
        if len(plus) > _PATCH_LINE_LIMIT:
            console.print(Text("... (truncated)", style="dim"))
        return
    if finding.suggested_fix:
        line = Text("Suggested fix: ", style="dim")
        line.append(_plain(finding.suggested_fix, ascii_mode, finding))
        console.print(line)


def _print_dismissed(console: Console, findings: list[Finding], ascii_mode: bool) -> None:
    rows = sorted(findings, key=lambda finding: (finding.file, finding.line))
    console.print(Text(f"Dismissed by local AI (not blocking): {len(rows)}", style="dim"))
    width = console.width or 80
    for finding in rows:
        reason = _plain(finding.risk_reasoning or finding.explanation or "", ascii_mode, finding)
        loc = _plain(f"{finding.file}:{finding.line}", ascii_mode)
        text = f"  {loc}  {reason}".rstrip()
        console.print(Text(_cut(text, width)))


def render_report(findings: list[Finding], ascii_mode: bool = False) -> None:
    console = _console()
    cache: dict[str, list[str] | None] = {}
    live = sorted(
        _live(findings),
        key=lambda finding: (_SEVERITY_RANK.get(finding.severity, 9), finding.file, finding.line),
    )
    for finding in live:
        console.print()
        _print_heading(console, finding, ascii_mode)
        source_line = _print_frame(console, finding, cache, ascii_mode)
        ai_text = _ai_text(finding)
        if ai_text:
            ai_text = _plain(ai_text, ascii_mode, finding)
            line = Text("Local AI", style="dim")
            if finding.is_real_risk is True:
                line.append(" (real risk)", style="bold red")
            line.append(": ", style="dim")
            line.append(ai_text)
            console.print(line)
        _print_fix(console, finding, source_line, ascii_mode)

    dismissed = _dismissed(findings)
    if dismissed:
        console.print()
        _print_dismissed(console, dismissed, ascii_mode)

    notes = {
        finding.explanation
        for finding in findings
        if finding.is_real_risk is None
        and finding.explanation
        and finding.explanation.startswith(NOT_REVIEWED_PREFIX)
    }
    for note in sorted(notes):
        console.print(Text(_plain(note, ascii_mode), style="dim"))
    unavailable = {
        finding.explanation
        for finding in findings
        if finding.is_real_risk is None
        and finding.explanation
        and finding.explanation.startswith(LLM_UNAVAILABLE_PREFIX)
    }
    for note in sorted(unavailable):
        console.print(Text(_plain(friendly_unavailable(note), ascii_mode), style="dim"))


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

    timings: dict[str, float] = {}
    try:
        # Every layer runs. There is no early return for non-Python commits.
        mark = time.perf_counter()
        imported = run_import_check(staged)
        timings["import_check"] = time.perf_counter() - mark
        mark = time.perf_counter()
        scanned = run_security_scan(staged)
        timings["security_scan"] = time.perf_counter() - mark
        mark = time.perf_counter()
        consistent = run_consistency(staged)
        timings["consistency"] = time.perf_counter() - mark
        findings = imported + scanned + consistent
        findings = [finding for finding in findings if finding.line in added.get(finding.file, ())]
        mark = time.perf_counter()
        enrich([finding for finding in findings if finding.severity in ("high", "medium")])
        timings["ai"] = time.perf_counter() - mark
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
    live = _live(findings)
    if blocked:
        status = "blocked"
    elif live:
        status = "warning"
    else:
        status = "passed"

    verdict_banner(status, _summary_counts(status, live, findings, len(staged), ascii_mode), ascii_mode)
    print_checks(findings, timings, ascii_mode)
    if args.banner or blocked:
        robot_banner(ascii_mode, "blocked" if blocked else "idle")
    if findings:
        render_report(findings, ascii_mode)

    if override:
        _console().print(
            Text(
                f"OVERRIDE: committing past {len(blocking)} high-severity "
                f"issue(s) because VERICODE_OVERRIDE=1.",
                style="bold yellow",
            )
        )
        return 0
    if not blocking:
        if status == "warning":
            render_next_steps(status, findings, ascii_mode)
        return 0

    render_next_steps("blocked", findings, ascii_mode)
    return 1


if __name__ == "__main__":
    sys.exit(main())
