"""Terminal report for the commit gate. Display only.

Colors are applied with Rich Text styles, never with inline markup tags, so
finding text such as "[red]" is printed literally. A new Console is created
on each call, after use_ascii() may have switched Windows stdout to UTF-8.
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from typing import Iterator

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

from vericode.shared.finding import Finding

# Navy (#0B2545) is part of the palette but is too dark to use as a border
# on a dark terminal, so borders and labels use dim gray instead.
_THEME = Theme(
    {
        "teal": "#13A8A8",
        "orange": "#FF7A1A",
        "red": "#E5384F",
        "navy": "#0B2545",
        "muted": "#8A94A6",
    }
)

_PATCH_LINE_LIMIT = 12

_SEVERITY_DISPLAY: dict[str, tuple[str, str, str]] = {
    "high": ("CRITICAL", "red", "critical"),
    "medium": ("WARNING", "orange", "warning"),
    "low": ("INFO", "teal", "info"),
}

_UNICODE_SYMBOLS = {
    "passed": "✔",
    "critical": "✖",
    "warning": "⚠",
    "info": "ℹ",
    "offline": "●",
    "divider": "─",
}

_ASCII_SYMBOLS = {
    "passed": "[OK]",
    "critical": "[X]",
    "warning": "[!]",
    "info": "[i]",
    "offline": "*",
    "divider": "-",
}

_UNICODE_FACES: dict[str, str] = {
    "idle": "[ ◉‿◉ ]",
    "scanning": "[ ◔_◔ ]",
    "warning": "[ ◉_◉ ]",
    "blocked": "[ ✖_✖ ]",
    "passed": "[ ^‿^ ]",
}

_ASCII_FACES: dict[str, str] = {
    "idle": "[ o_o ]",
    "scanning": "[ o.o ]",
    "warning": "[ o_O ]",
    "blocked": "[ x_x ]",
    "passed": "[ ^_^ ]",
}

# Five lines is the maximum. ASCII uses only "+", "-", "|", "o", "_", and spaces.
_UNICODE_BANNER = (
    "┌──────┐",
    "│ ◉  ◉ │",
    "│  ‿   │",
    "└──────┘",
)

_ASCII_BANNER = (
    "+------+",
    "| o  o |",
    "|  _   |",
    "+------+",
)


def _console() -> Console:
    """Build a console at call time. Never cached, never forced into color."""
    # soft_wrap keeps piped hook logs from hard-breaking sentences at column 80.
    return Console(
        markup=False,
        highlight=False,
        emoji=False,
        soft_wrap=True,
        theme=_THEME,
    )


def _symbols(ascii_mode: bool) -> dict[str, str]:
    return _ASCII_SYMBOLS if ascii_mode else _UNICODE_SYMBOLS


def _face(status: str, ascii_mode: bool) -> str:
    faces = _ASCII_FACES if ascii_mode else _UNICODE_FACES
    return faces.get(status, faces["idle"])


def _has_text(value: str | None) -> bool:
    return value is not None and value != ""


def _stdout_isatty() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


class _LenientStdout:
    """Forwards writes, replacing characters the stream cannot encode.

    Rich re-raises UnicodeEncodeError. This wrapper is only installed when
    the stream cannot be switched to errors="replace" itself.
    """

    def __init__(self, stream):
        self._stream = stream

    def write(self, text: str) -> int:
        try:
            return self._stream.write(text)
        except UnicodeEncodeError:
            encoding = getattr(self._stream, "encoding", None) or "ascii"
            safe = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
            return self._stream.write(safe)

    def __getattr__(self, name: str):
        return getattr(self._stream, name)


def _prepare_stdout() -> None:
    """Make stdout accept our output before anything is printed.

    On Windows, ask for UTF-8. If that fails, keep the current encoding but
    replace characters it cannot store. A stream with no reconfigure is wrapped
    so a later print cannot raise UnicodeEncodeError.
    """
    stream = sys.stdout
    if isinstance(stream, _LenientStdout):
        return
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is not None:
        if sys.platform == "win32":
            try:
                reconfigure(encoding="utf-8", errors="replace")
                return
            except Exception:
                pass
        try:
            reconfigure(errors="replace")
            return
        except Exception:
            pass
    if getattr(stream, "errors", None) in (None, "strict"):
        sys.stdout = _LenientStdout(stream)


def use_ascii(flag: bool) -> bool:
    """True when output must stay 7-bit ASCII.

    On Windows, try UTF-8 first. If that succeeds, Unicode is allowed unless
    the flag or VERICODE_ASCII forces ASCII. Call this before printing.
    """
    _prepare_stdout()

    if flag or os.environ.get("VERICODE_ASCII") == "1":
        return True

    encoding = getattr(sys.stdout, "encoding", None) or ""
    return "utf" not in encoding.lower()


def override_hint() -> str:
    """One-line shell snippet for allowing a blocked commit.

    Git Bash on Windows still reports sys.platform == "win32", but it cannot
    run the PowerShell assignment. MSYSTEM or SHELL means a Unix-style shell.
    """
    if os.environ.get("MSYSTEM") or os.environ.get("SHELL"):
        return "VERICODE_OVERRIDE=1 git commit"
    if sys.platform == "win32":
        return "$env:VERICODE_OVERRIDE=1; git commit"
    return "VERICODE_OVERRIDE=1 git commit"


@contextmanager
def scanning(ascii_mode: bool) -> Iterator[None]:
    """Show a spinner only on a real terminal. Rich clears it on exit.

    Piped output and pre-commit (no TTY) skip the spinner, so no cursor
    codes are written into a captured log.
    """
    if not _stdout_isatty():
        yield
        return

    spinner = "line" if ascii_mode else "dots"
    with _console().status("Scanning staged files...", spinner=spinner):
        yield


def header(status: str, ascii_mode: bool) -> None:
    """One brand line: outcome face, name, and the offline badge."""
    line = Text()
    line.append(_face(status, ascii_mode))
    line.append(" ")
    line.append("VERICODE", style="bold teal")
    line.append("  ")
    line.append(_symbols(ascii_mode)["offline"], style="teal")
    line.append(" Running 100% on this device", style="muted")
    _console().print(line)


def robot_banner(ascii_mode: bool) -> None:
    """Small robot head. At most five lines."""
    art = _ASCII_BANNER if ascii_mode else _UNICODE_BANNER
    console = _console()
    for row in art:
        console.print(Text(row, style="teal"))
    console.print()


def render_finding(finding: Finding, ascii_mode: bool) -> None:
    """Print one finding. Missing optional fields are omitted, not shown as None."""
    label, style, symbol_key = _SEVERITY_DISPLAY.get(
        finding.severity,
        (finding.severity.upper(), "muted", "info"),
    )
    symbols = _symbols(ascii_mode)
    console = _console()

    title = Text()
    title.append(f"{symbols[symbol_key]} ", style=style)
    title.append(label, style=f"bold {style}")
    title.append(f"  {finding.file}:{finding.line}", style="muted")
    console.print(title)
    # Plain Text, markup disabled: brackets in the message stay literal.
    console.print(Text(f"  {finding.message}"))

    _detail(console, "Fix:", finding.suggested_fix, "orange")
    _detail(console, "Why:", finding.explanation, "muted")
    _patch(console, finding.fixed_code)
    _detail(console, "Risk note:", finding.risk_reasoning, "muted")
    console.print()


def _detail(console: Console, label: str, value: str | None, style: str) -> None:
    if not _has_text(value):
        return
    line = Text("  ")
    line.append(f"{label} ", style="muted")
    line.append(value or "", style=style)
    console.print(line)


def _patch(console: Console, fixed_code: str | None) -> None:
    if not _has_text(fixed_code):
        return
    lines = (fixed_code or "").splitlines() or [""]
    shown = lines[:_PATCH_LINE_LIMIT]
    console.print(Text("  Patch:", style="muted"))
    for line in shown:
        console.print(Text(f"    {line}"))
    if len(lines) > _PATCH_LINE_LIMIT:
        console.print(Text("    ... (truncated)", style="muted"))


def _counts(findings: list[Finding]) -> str:
    names = (("high", "critical"), ("medium", "warning"), ("low", "info"))
    parts: list[str] = []
    for severity, name in names:
        count = sum(1 for finding in findings if finding.severity == severity)
        if count:
            parts.append(f"{count} {name}")
    return ", ".join(parts)


def render_summary(
    findings: list[Finding],
    blocked: bool,
    elapsed_seconds: float,
    files_scanned: int,
    ascii_mode: bool,
) -> None:
    """Final line. Blocked commits also get a one-line override hint."""
    console = _console()
    noun = "file" if files_scanned == 1 else "files"
    scanned = f"{files_scanned} {noun} scanned"
    timing = f"{scanned}. {elapsed_seconds:.1f}s"

    if blocked:
        counts = _counts(findings) or "0 critical"
        console.print(Text(f"Commit blocked. {counts}.", style="bold red"))
        console.print(Text(f"Override: {override_hint()}", style="muted"))
        console.print(Text(timing, style="muted"))
        return

    if findings:
        counts = _counts(findings)
        console.print(Text(f"Commit allowed. {counts}.", style="orange"))
        console.print(Text(timing, style="muted"))
        return

    line = Text()
    line.append(f"{_face('passed', ascii_mode)} ")
    line.append(f"{scanned}, no issues. {elapsed_seconds:.1f}s", style="teal")
    console.print(line)


def render_override(ascii_mode: bool) -> None:
    """Shown when VERICODE_OVERRIDE=1 allows a commit that would have blocked."""
    line = Text()
    line.append(f"{_face('warning', ascii_mode)} ")
    line.append("Override active. Commit allowed.", style="bold orange")
    _console().print(line)


def render_error(message: str, hint: str, ascii_mode: bool) -> None:
    """Short error panel. Does not print a traceback."""
    body = Text(message, style="bold red")
    if hint:
        body.append("\n")
        body.append(hint, style="muted")
    _console().print(
        Panel(
            body,
            title="Error",
            border_style="muted",
            box=box.ASCII if ascii_mode else box.SQUARE,
        )
    )
