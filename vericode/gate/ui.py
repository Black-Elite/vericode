"""Terminal report for the commit gate. Display only.

Colors are applied with Rich Text styles, never with inline markup tags, so
finding text such as "[red]" is printed literally. A new Console is created
on each call, after use_ascii() may have switched Windows stdout to UTF-8.
"""

from __future__ import annotations

import os
import re
import sys
from contextlib import contextmanager
from typing import Iterator

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

from vericode.llm_explain.explainer import LLM_UNAVAILABLE_PREFIX
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
# False until the doctor command is merged. The line below is not printed while this is false.
SHOW_DOCTOR_STEP = False
_DOCTOR_LINE = "Run vericode doctor."

_TOKEN_SHAPES = re.compile(r"ghp_[A-Za-z0-9]+|sk-[A-Za-z0-9_-]+|AKIA[A-Za-z0-9]+|xox[A-Za-z0-9-]+")
_QUOTED_SECRET = re.compile(r"""(["'])([^"'\n]{9,})\1""")

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

# Same head, but the face matches a blocked commit (like the header's ✖_✖).
_UNICODE_BANNER_BLOCKED = (
    "┌──────┐",
    "│ ✖  ✖ │",
    "│  ︵  │",
    "└──────┘",
)

_ASCII_BANNER_BLOCKED = (
    "+------+",
    "| x  x |",
    "|  ^   |",
    "+------+",
)


def console_options() -> dict:
    """Color stays off unless the hook opts in. NO_COLOR wins over that opt-in."""
    if "NO_COLOR" in os.environ:
        return {"no_color": True, "force_terminal": False}
    if os.environ.get("VERICODE_COLOR") == "1":
        # legacy_windows would call the Win32 console API and emit no codes on a pipe.
        return {"force_terminal": True, "color_system": "standard", "legacy_windows": False}
    return {}


def _console() -> Console:
    """Build a console at call time. Never cached, never forced into color."""
    # soft_wrap keeps piped hook logs from hard-breaking sentences at column 80.
    return Console(
        markup=False,
        highlight=False,
        emoji=False,
        soft_wrap=True,
        theme=_THEME,
        **console_options(),
    )


def _symbols(ascii_mode: bool) -> dict[str, str]:
    return _ASCII_SYMBOLS if ascii_mode else _UNICODE_SYMBOLS


def _face(status: str, ascii_mode: bool) -> str:
    faces = _ASCII_FACES if ascii_mode else _UNICODE_FACES
    return faces.get(status, faces["idle"])


def _has_text(value: str | None) -> bool:
    return value is not None and value != ""


def mask_quotes_for(finding: Finding | None) -> bool:
    """The only layer check for quoted strings. Tokens are masked everywhere."""
    return finding is not None and finding.layer == "security_scan"


def mask_secrets(text: str, *, mask_quotes: bool = False) -> str:
    """Hide token shapes. Long quotes are hidden only when mask_quotes is set."""

    def hide(value: str) -> str:
        return value[:4] + "****"

    text = _TOKEN_SHAPES.sub(lambda match: hide(match.group(0)), text)
    if not mask_quotes:
        return text

    def hide_quoted(match: re.Match) -> str:
        quote, body = match.group(1), match.group(2)
        return f"{quote}{hide(body)}{quote}"

    return _QUOTED_SECRET.sub(hide_quoted, text)


def fold_ascii(text: str) -> str:
    """ASCII mode: dashes, quotes, and ellipsis become plain text. Anything else is '?'."""
    text = (
        text.replace("\u2014", "-")
        .replace("\u2013", "-")
        .replace("\u2018", "'")
        .replace("\u2019", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2026", "...")
    )
    return "".join(char if ord(char) < 128 else "?" for char in text)


def display_text(text: str, ascii_mode: bool, *, mask_quotes: bool = False) -> str:
    text = mask_secrets(text, mask_quotes=mask_quotes)
    if ascii_mode:
        return fold_ascii(text)
    return text


def friendly_unavailable(text: str) -> str:
    """Drop the matching prefix. The user sees only the friendly sentence."""
    if not text.startswith(LLM_UNAVAILABLE_PREFIX):
        return text
    rest = text[len(LLM_UNAVAILABLE_PREFIX):].strip()
    if rest.startswith("(") and rest.endswith(")"):
        return rest[1:-1].strip()
    return rest


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


def override_forms() -> list[str]:
    """Each override command, whole. A Windows hook with a Unix shell gets both."""
    unix = "VERICODE_OVERRIDE=1 git commit"
    powershell = "$env:VERICODE_OVERRIDE=1; git commit"
    if sys.platform == "win32" and (os.environ.get("MSYSTEM") or os.environ.get("SHELL")):
        return [unix, powershell]
    if sys.platform == "win32":
        return [powershell]
    return [unix]


def override_hint() -> str:
    """One-line shell snippet for allowing a blocked commit.

    Git Bash on Windows still reports sys.platform == "win32", but it cannot
    run the PowerShell assignment. MSYSTEM or SHELL means a Unix-style shell,
    so a Windows hook names both forms. The report prints those forms on
    separate lines so neither command is split.
    """
    forms = override_forms()
    if len(forms) == 2:
        return f"{forms[0]}  (PowerShell: {forms[1]})"
    return forms[0]


def _ai_fix(text: str) -> str | None:
    if "ollama serve" in text:
        return "Start the local AI: ollama serve"
    marker = "ollama pull "
    if marker in text:
        command = text[text.index(marker):].split(")")[0].strip()
        return f"Pull the local model: {command}"
    if "VERICODE_TIMEOUT" in text:
        return "Try a smaller model or raise VERICODE_TIMEOUT"
    if text.startswith(LLM_UNAVAILABLE_PREFIX):
        return "Local AI failed. Showing static checks only."
    return None


def render_next_steps(status: str, findings: list[Finding], ascii_mode: bool) -> None:
    """Footer. Passed commits stop at the verdict. Doctor stays hidden until the constant flips."""
    console = _console()
    if status == "warning":
        console.print(Text(display_text("Commit allowed. Review the warnings when you can.", ascii_mode)))
        return
    if status != "blocked":
        return
    console.print(Text("Next steps", style="bold"))
    console.print(Text("1) Fix the lines above, then git add and git commit again."))
    forms = override_forms()
    if len(forms) == 1:
        console.print(Text(f"2) To commit anyway: {forms[0]}"))
    else:
        console.print(Text("2) To commit anyway:"))
        for form in forms:
            console.print(Text(f"   {form}"))
    unavailable = next(
        (
            finding.explanation
            for finding in findings
            if finding.is_real_risk is None
            and finding.explanation
            and finding.explanation.startswith(LLM_UNAVAILABLE_PREFIX)
        ),
        None,
    )
    if unavailable:
        fix = _ai_fix(unavailable)
        if fix:
            console.print(Text(display_text(f"3) {fix}", ascii_mode)))
    if SHOW_DOCTOR_STEP:
        console.print(Text(display_text(_DOCTOR_LINE, ascii_mode)))


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
    verdict_banner(status, "", ascii_mode)


def verdict_banner(status: str, counts: str, ascii_mode: bool) -> None:
    """First line: face, name, verdict, counts. The offline badge is the next dim line."""
    word = {"blocked": "Blocked", "warning": "Warning", "passed": "Passed"}.get(
        status, status.capitalize()
    )
    word_style = {"blocked": "bold red", "warning": "bold orange", "passed": "bold teal"}.get(
        status, "bold"
    )
    line = Text()
    line.append(_face(status, ascii_mode))
    line.append(" ")
    line.append("VERICODE", style="bold teal")
    line.append("  ")
    line.append(word, style=word_style)
    if counts:
        line.append(": ")
        line.append(counts)
    _console().print(line)
    badge = Text()
    badge.append(_symbols(ascii_mode)["offline"], style="muted")
    badge.append(" Running 100% on this device", style="muted")
    _console().print(badge)


def robot_banner(ascii_mode: bool, status: str = "idle") -> None:
    """Small robot head. At most five lines. Frowns when the commit is blocked."""
    if status == "blocked":
        art = _ASCII_BANNER_BLOCKED if ascii_mode else _UNICODE_BANNER_BLOCKED
    else:
        art = _ASCII_BANNER if ascii_mode else _UNICODE_BANNER
    console = _console()
    for row in art:
        console.print(Text(row, style="teal"))


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
    quotes = mask_quotes_for(finding)
    console.print(Text(f"  {display_text(finding.message, ascii_mode, mask_quotes=quotes)}"))

    _detail(console, "Fix:", finding.suggested_fix, "orange", ascii_mode, quotes)
    shown_why = finding.explanation
    if shown_why and shown_why.startswith(LLM_UNAVAILABLE_PREFIX):
        shown_why = friendly_unavailable(shown_why)
    _detail(console, "Why:", shown_why, "muted", ascii_mode, quotes)
    _patch(console, finding.fixed_code, ascii_mode, quotes)
    _detail(console, "Risk note:", finding.risk_reasoning, "muted", ascii_mode, quotes)
    console.print()


def _detail(
    console: Console,
    label: str,
    value: str | None,
    style: str,
    ascii_mode: bool,
    mask_quotes: bool,
) -> None:
    if not _has_text(value):
        return
    line = Text("  ")
    line.append(f"{label} ", style="muted")
    line.append(display_text(value or "", ascii_mode, mask_quotes=mask_quotes), style=style)
    console.print(line)


def _patch(console: Console, fixed_code: str | None, ascii_mode: bool, mask_quotes: bool) -> None:
    if not _has_text(fixed_code):
        return
    lines = display_text(fixed_code or "", ascii_mode, mask_quotes=mask_quotes).splitlines() or [""]
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
