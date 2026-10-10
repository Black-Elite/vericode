"""Display tests for the commit-gate report. No scanner behavior."""

import io
import subprocess
import sys

from vericode.gate.cli import (
    LLM_UNAVAILABLE_PREFIX,
    NOT_REVIEWED_PREFIX,
    added_lines,
    main,
    render_report,
)
from vericode.gate.ui import (
    header,
    override_hint,
    render_error,
    render_finding,
    render_summary,
    robot_banner,
    use_ascii,
)
from vericode.shared.finding import Finding

HIGH = Finding(
    layer="import_check",
    file="sample.py",
    line=1,
    severity="high",
    message="'pandas_fast_reader' does not match any package on PyPI.",
    suggested_fix="Did you mean 'pandas'?",
)

MEDIUM = Finding(
    layer="security_scan",
    file="app.py",
    line=4,
    severity="medium",
    message="possible shell injection",
)

WITH_EXPLANATION = Finding(
    layer="security_scan",
    file="app.py",
    line=8,
    severity="high",
    message="hardcoded API key",
    explanation="This string is a live credential.",
    fixed_code="API_KEY = os.environ['API_KEY']\n",
    risk_reasoning="The key would ship in the repository.",
)

ALL_EMPTY = Finding(
    layer="import_check",
    file="quiet.py",
    line=2,
    severity="low",
    message="installed package is missing from this environment",
)

BRACKETS = Finding(
    layer="import_check",
    file="markup.py",
    line=3,
    severity="low",
    message="code [0] uses [red]hidden[/red] and [OK]",
)


class _Stdout:
    """Stand-in stdout so encoding checks do not depend on the host console."""

    def __init__(self, encoding: str | None, reconfigure_error: Exception | None = None):
        self.encoding = encoding
        self.reconfigure_error = reconfigure_error

    def reconfigure(self, *args, **kwargs) -> None:
        if self.reconfigure_error is not None:
            raise self.reconfigure_error
        self.encoding = kwargs.get("encoding", self.encoding)

    def isatty(self) -> bool:
        return False


def test_ascii_output_is_7bit(capsys, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    header("blocked", ascii_mode=True)
    robot_banner(ascii_mode=True)
    for finding in (HIGH, MEDIUM, WITH_EXPLANATION, ALL_EMPTY, BRACKETS):
        render_finding(finding, ascii_mode=True)
    render_summary(
        [HIGH, MEDIUM],
        blocked=True,
        elapsed_seconds=0.8,
        files_scanned=2,
        ascii_mode=True,
    )
    render_summary([], blocked=False, elapsed_seconds=0.8, files_scanned=2, ascii_mode=True)
    render_error("Not a git repository or git failed.", "Run inside a repository.", ascii_mode=True)

    output = capsys.readouterr().out
    assert output
    assert all(ord(char) < 128 for char in output)
    assert "[X]" in output
    assert "[ ^_^ ]" in output


def test_unicode_symbols_when_encoding_is_utf8(monkeypatch, capsys):
    monkeypatch.delenv("VERICODE_ASCII", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    captured = sys.stdout
    sys.stdout = _Stdout("utf-8")
    try:
        assert use_ascii(False) is False
    finally:
        sys.stdout = captured

    header("blocked", ascii_mode=False)
    header("passed", ascii_mode=False)
    render_finding(HIGH, ascii_mode=False)
    output = capsys.readouterr().out
    assert "✖" in output
    assert "●" in output
    assert "‿" in output
    assert "CRITICAL" in output


def test_none_fields_are_omitted(capsys):
    render_finding(ALL_EMPTY, ascii_mode=True)
    output = capsys.readouterr().out
    assert "None" not in output
    assert "Fix:" not in output
    assert "Why:" not in output
    assert "Patch:" not in output
    assert "Risk note:" not in output
    assert "INFO" in output
    assert "quiet.py:2" in output


def test_severity_labels_and_optional_lines(capsys):
    render_finding(HIGH, ascii_mode=True)
    render_finding(MEDIUM, ascii_mode=True)
    render_finding(WITH_EXPLANATION, ascii_mode=True)
    output = capsys.readouterr().out

    assert "CRITICAL" in output
    assert "WARNING" in output
    assert "Fix: Did you mean 'pandas'?" in output
    assert "Why: This string is a live credential." in output
    assert "Patch:" in output
    assert "API_KEY = os.environ['API_KEY']" in output
    assert "Risk note: The key would ship in the repository." in output
    high_block = output.split("WARNING")[0]
    assert "Why:" not in high_block
    assert "Patch:" not in high_block


def test_brackets_print_literally_in_both_modes(capsys):
    message = BRACKETS.message
    render_finding(BRACKETS, ascii_mode=False)
    render_finding(BRACKETS, ascii_mode=True)
    output = capsys.readouterr().out
    assert output.count(message) == 2
    assert "[0]" in output
    assert "[red]hidden[/red]" in output
    assert "[OK]" in output


def test_use_ascii_env_forces_ascii_even_on_utf8(monkeypatch):
    monkeypatch.setenv("VERICODE_ASCII", "1")
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "stdout", _Stdout("utf-8"))
    assert use_ascii(False) is True


def test_use_ascii_cp1252_when_reconfigure_fails(monkeypatch):
    monkeypatch.delenv("VERICODE_ASCII", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        sys,
        "stdout",
        _Stdout("cp1252", reconfigure_error=OSError("no utf-8")),
    )
    assert use_ascii(False) is True


def test_use_ascii_flag(monkeypatch):
    monkeypatch.delenv("VERICODE_ASCII", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "stdout", _Stdout("utf-8"))
    assert use_ascii(True) is True


def _clear_shell_markers(monkeypatch) -> None:
    monkeypatch.delenv("MSYSTEM", raising=False)
    monkeypatch.delenv("SHELL", raising=False)


def test_override_hint_powershell_on_windows(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "win32")
    _clear_shell_markers(monkeypatch)
    assert override_hint() == "$env:VERICODE_OVERRIDE=1; git commit"
    render_summary([HIGH], blocked=True, elapsed_seconds=0.8, files_scanned=1, ascii_mode=True)
    output = capsys.readouterr().out
    assert "Override: $env:VERICODE_OVERRIDE=1; git commit" in output


def test_override_hint_msystem_uses_unix_syntax(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    _clear_shell_markers(monkeypatch)
    monkeypatch.setenv("MSYSTEM", "MINGW64")
    assert override_hint() == (
        "VERICODE_OVERRIDE=1 git commit  (PowerShell: $env:VERICODE_OVERRIDE=1; git commit)"
    )


def test_override_hint_shell_uses_unix_syntax(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    _clear_shell_markers(monkeypatch)
    monkeypatch.setenv("SHELL", "/usr/bin/bash")
    assert override_hint() == (
        "VERICODE_OVERRIDE=1 git commit  (PowerShell: $env:VERICODE_OVERRIDE=1; git commit)"
    )


def test_override_hint_posix(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")
    _clear_shell_markers(monkeypatch)
    assert override_hint() == "VERICODE_OVERRIDE=1 git commit"
    render_summary(
        [HIGH, MEDIUM],
        blocked=True,
        elapsed_seconds=1.2,
        files_scanned=3,
        ascii_mode=True,
    )
    output = capsys.readouterr().out
    assert "Commit blocked. 1 critical, 1 warning." in output
    assert "Override: VERICODE_OVERRIDE=1 git commit" in output
    assert "$env:" not in output


def test_ascii_banner_is_short_and_plain(capsys):
    robot_banner(ascii_mode=True)
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert 1 <= len(lines) <= 5
    allowed = set("+-|o_ ")
    assert all(set(line) <= allowed for line in lines)


def test_fixed_code_truncates_after_twelve_lines(capsys):
    code = "\n".join(f"line {number}" for number in range(1, 15))
    finding = Finding(
        layer="security_scan",
        file="long.py",
        line=1,
        severity="medium",
        message="long patch",
        fixed_code=code,
    )
    render_finding(finding, ascii_mode=True)
    output = capsys.readouterr().out
    assert "line 12" in output
    assert "line 13" not in output
    assert "... (truncated)" in output


def _patch_added_lines(monkeypatch, lines: dict[str, set[int]] | None = None) -> None:
    monkeypatch.setattr("vericode.gate.cli.added_lines", lambda: {} if lines is None else lines)


def _stub_scanners(monkeypatch, findings: list[Finding], files: list[str]) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("VERICODE_ASCII", raising=False)
    monkeypatch.setattr("vericode.gate.cli.get_staged_files", lambda: files)
    added: dict[str, set[int]] = {}
    for finding in findings:
        added.setdefault(finding.file, set()).add(finding.line)
    _patch_added_lines(monkeypatch, added)
    monkeypatch.delenv("VERICODE_COLOR", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr("vericode.gate.cli.run_import_check", lambda staged: findings)
    monkeypatch.setattr("vericode.gate.cli.run_security_scan", lambda staged: [])
    monkeypatch.setattr("vericode.gate.cli.run_consistency", lambda staged: [])
    monkeypatch.setattr("vericode.gate.cli.enrich", lambda items: items)


def test_clean_run_prints_one_passed_header(monkeypatch, capsys):
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    _stub_scanners(monkeypatch, [], ["a.py", "b.py"])

    assert main([]) == 0
    output = capsys.readouterr().out
    assert output.count("VERICODE") == 1
    assert "Passed:" in output
    assert "Scanning staged files" not in output


def test_non_python_files_are_counted(monkeypatch, capsys):
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    _stub_scanners(monkeypatch, [], ["app.py", "config.yaml"])

    assert main([]) == 0
    output = capsys.readouterr().out
    assert "Passed:" in output
    assert "Blocked:" not in output


def test_yaml_only_with_no_findings_passes(monkeypatch, capsys):
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    _stub_scanners(monkeypatch, [], ["config.yaml"])

    assert main([]) == 0
    output = capsys.readouterr().out
    assert "Passed:" in output
    assert "[ ^_^ ]" in output or "[ ^‿^ ]" in output
    assert "No Python files" not in output


YAML_SECRET = Finding(
    layer="security_scan",
    file="config.yaml",
    line=2,
    severity="high",
    message="hardcoded API key in config",
)


def test_yaml_secret_on_added_line_blocks(monkeypatch, capsys):
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    _stub_scanners(monkeypatch, [YAML_SECRET], ["config.yaml"])
    _patch_added_lines(monkeypatch, {"config.yaml": {2}})

    assert main([]) == 1
    output = capsys.readouterr().out
    assert "config.yaml" in output
    assert "Blocked:" in output
    assert "No Python files" not in output


def test_block_and_override(monkeypatch, capsys):
    _stub_scanners(monkeypatch, [HIGH, MEDIUM], ["sample.py"])

    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    assert main([]) == 1
    blocked = capsys.readouterr().out
    assert "Blocked:" in blocked
    assert "1 must-fix" in blocked
    assert "Next steps" in blocked
    assert "git add and git commit again." in blocked
    assert blocked.count("Running 100% on this device") == 1

    monkeypatch.setenv("VERICODE_OVERRIDE", "1")
    assert main([]) == 0
    allowed = capsys.readouterr().out
    assert "OVERRIDE: committing past 1 high-severity issue(s)" in allowed
    assert "[ o_O ]" in allowed or "[ ◉_◉ ]" in allowed
    assert "Commit blocked" not in allowed
    assert "Blocked:" not in allowed


def test_unadded_line_is_hidden_and_does_not_block(monkeypatch, capsys):
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    _stub_scanners(monkeypatch, [HIGH], ["sample.py"])
    _patch_added_lines(monkeypatch, {"sample.py": {99}})

    assert main([]) == 0
    output = capsys.readouterr().out
    assert "sample.py" not in output
    assert "Commit blocked" not in output
    assert "Blocked:" not in output
    assert "Passed:" in output


def test_added_line_is_shown(monkeypatch, capsys):
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    _stub_scanners(monkeypatch, [HIGH], ["sample.py"])
    _patch_added_lines(monkeypatch, {"sample.py": {1}})

    assert main([]) == 1
    output = capsys.readouterr().out
    assert "sample.py" in output
    assert "Blocked:" in output


def test_snapshot_file_not_found_is_specific(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("vericode.gate.cli.get_staged_files", lambda: ["a.py"])
    _patch_added_lines(monkeypatch)

    def explode(files):
        raise FileNotFoundError(r"C:\vericode\import_check\data\pypi_all.txt is missing")

    monkeypatch.setattr("vericode.gate.cli.run_import_check", explode)
    assert main([]) == 2
    output = capsys.readouterr().out
    assert "Offline package list not found." in output
    assert "Run ./setup.sh while online first." in output
    assert "Traceback" not in output


def test_other_file_not_found_names_the_file(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("vericode.gate.cli.get_staged_files", lambda: ["a.py"])
    _patch_added_lines(monkeypatch)

    def explode(files):
        raise FileNotFoundError(2, "No such file or directory", "C:/missing/other.txt")

    monkeypatch.setattr("vericode.gate.cli.run_import_check", explode)
    assert main([]) == 2
    output = capsys.readouterr().out
    assert "File not found: C:/missing/other.txt" in output
    assert "Offline package list not found" not in output


def test_git_failure_returns_2(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")

    def explode():
        raise subprocess.CalledProcessError(1, ["git"])

    monkeypatch.setattr("vericode.gate.cli.get_staged_files", explode)
    _patch_added_lines(monkeypatch)
    assert main(["--banner"]) == 2
    output = capsys.readouterr().out
    assert "Not a git repository or git failed." in output
    assert "Traceback" not in output


MARKUP_TEXT = "[0] [red] [x] [/]"


def test_markup_in_findings_prints_literally(capsys, monkeypatch):
    from rich.console import Console

    monkeypatch.setattr(
        "vericode.gate.cli._console",
        lambda: Console(highlight=False, width=240, height=40, legacy_windows=False),
    )
    reviewed = Finding(
        layer="security_scan",
        file="[red].py",
        line=4,
        severity="high",
        message=f"see {MARKUP_TEXT}",
        fixed_code=f"code {MARKUP_TEXT}",
        explanation=f"why {MARKUP_TEXT}",
        is_real_risk=True,
    )
    reasoned = Finding(
        layer="security_scan",
        file="[red].py",
        line=5,
        severity="medium",
        message="risk row",
        risk_reasoning=f"risk {MARKUP_TEXT}",
        suggested_fix=f"fix {MARKUP_TEXT}",
        is_real_risk=False,
    )
    noted = Finding(
        layer="security_scan",
        file="[red].py",
        line=6,
        severity="low",
        message="note row",
        explanation=f"note {MARKUP_TEXT}",
        suggested_fix=f"fix {MARKUP_TEXT}",
        is_real_risk=None,
    )
    render_report([reviewed, reasoned, noted])
    output = capsys.readouterr().out
    assert "[red].py" in output
    assert f"see {MARKUP_TEXT}" in output
    assert f"code {MARKUP_TEXT}" in output
    assert f"why {MARKUP_TEXT}" in output
    assert f"risk {MARKUP_TEXT}" in output
    assert f"fix {MARKUP_TEXT}" in output
    assert f"note {MARKUP_TEXT}" in output


def _render(capsys, monkeypatch, findings):
    from rich.console import Console

    monkeypatch.setattr(
        "vericode.gate.cli._console",
        lambda: Console(highlight=False, width=240, height=40, legacy_windows=False),
    )
    render_report(findings)
    return capsys.readouterr().out


def test_ai_verdict_is_shown_in_words(capsys, monkeypatch):
    real = Finding(layer="security_scan", file="a.py", line=1, severity="high",
                   message="os.system", explanation="user input reaches the shell", is_real_risk=True)
    cleared = Finding(layer="security_scan", file="a.py", line=2, severity="low",
                      message="os.system", explanation="only today's date", is_real_risk=False)
    output = _render(capsys, monkeypatch, [real, cleared])
    assert "Local AI (real risk): user input reaches the shell" in output
    assert "Dismissed by local AI (not blocking): 1" in output
    assert "only today's date" in output
    assert output.index("user input reaches the shell") < output.index("Dismissed by local AI")


def test_cleared_finding_shows_no_fix(capsys, monkeypatch):
    cleared = Finding(layer="security_scan", file="a.py", line=2, severity="low",
                      message="os.system", explanation="only today's date", is_real_risk=False,
                      suggested_fix="Replace os.system()", fixed_code="subprocess.run([...])")
    output = _render(capsys, monkeypatch, [cleared])
    assert "Dismissed by local AI (not blocking): 1" in output
    assert "Fix: none needed" not in output
    assert "Replace os.system()" not in output
    assert "subprocess.run" not in output


def test_blocked_banner_frowns(capsys, monkeypatch):
    from rich.console import Console

    from vericode.gate import ui

    monkeypatch.setattr(ui, "_console", lambda: Console(width=80, legacy_windows=False))
    ui.robot_banner(ascii_mode=True, status="blocked")
    blocked = capsys.readouterr().out
    ui.robot_banner(ascii_mode=True)
    idle = capsys.readouterr().out
    assert "x  x" in blocked and "o  o" not in blocked
    assert "o  o" in idle


def test_ascii_report_is_7bit(capsys):
    finding = Finding(
        layer="security_scan",
        file="plain.py",
        line=1,
        severity="medium",
        message="plain issue",
        is_real_risk=True,
    )
    render_report([finding], ascii_mode=True)
    output = capsys.readouterr().out
    assert output
    assert all(ord(char) < 128 for char in output)


def test_added_lines_reads_unicode_and_invalid_bytes(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    note = repo / "note.py"
    note.write_text("●\n◉\né\n", encoding="utf-8")
    subprocess.run(["git", "add", "--", "note.py"], cwd=repo, check=True, capture_output=True)
    monkeypatch.chdir(repo)

    added = added_lines()
    assert added["note.py"] == {1, 2, 3}

    bad = repo / "bad.py"
    bad.write_bytes(b"\xff\n")
    subprocess.run(["git", "add", "--", "bad.py"], cwd=repo, check=True, capture_output=True)
    added_bad = added_lines()
    assert isinstance(added_bad, dict)


def test_blocked_hint_follows_the_shell(monkeypatch, capsys):
    _stub_scanners(monkeypatch, [HIGH], ["sample.py"])
    _patch_added_lines(monkeypatch, {"sample.py": {1}})
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("MSYSTEM", raising=False)
    monkeypatch.delenv("SHELL", raising=False)

    assert main([]) == 1
    assert "$env:VERICODE_OVERRIDE=1; git commit" in capsys.readouterr().out

    monkeypatch.setenv("MSYSTEM", "MINGW64")
    assert main([]) == 1
    mingw = capsys.readouterr().out
    assert "VERICODE_OVERRIDE=1 git commit" in mingw
    assert "$env:VERICODE_OVERRIDE=1; git commit" in mingw

    monkeypatch.delenv("MSYSTEM", raising=False)
    monkeypatch.setenv("SHELL", "/bin/bash")
    assert main([]) == 1
    bash = capsys.readouterr().out
    assert "VERICODE_OVERRIDE=1 git commit" in bash
    assert "$env:VERICODE_OVERRIDE=1; git commit" in bash


def test_main_cp1252_redirect_does_not_raise(monkeypatch):
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.delenv("VERICODE_ASCII", raising=False)
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    monkeypatch.delenv("PYTHONUTF8", raising=False)
    finding = Finding(
        layer="security_scan",
        file="app.py",
        line=1,
        severity="high",
        message="see ● and [red]",
        suggested_fix="use a literal",
    )
    monkeypatch.setattr("vericode.gate.cli.get_staged_files", lambda: ["app.py"])
    monkeypatch.setattr("vericode.gate.cli.added_lines", lambda: {"app.py": {1}})
    monkeypatch.setattr("vericode.gate.cli.run_import_check", lambda files: [finding])
    monkeypatch.setattr("vericode.gate.cli.run_security_scan", lambda files: [])
    monkeypatch.setattr("vericode.gate.cli.enrich", lambda items: items)

    assert main(["--banner"]) == 1
    stream.flush()
    text = buffer.getvalue().decode(stream.encoding or "utf-8", errors="replace")
    assert "Blocked:" in text
    assert "Traceback" not in text


def test_report_patch_keeps_indent_and_truncates(capsys, monkeypatch):
    from rich.console import Console

    monkeypatch.setattr(
        "vericode.gate.cli._console",
        lambda: Console(highlight=False, width=80, height=40, legacy_windows=False),
    )
    long_line = "token = " + ("A" * 120) + "_END"
    code = "\n".join([long_line, "if ok:", "    return 1"] + [f"line {n}" for n in range(4, 16)])
    finding = Finding(
        layer="security_scan",
        file="app.py",
        line=3,
        severity="high",
        message="hardcoded token",
        fixed_code=code,
        is_real_risk=True,
    )
    render_report([finding], ascii_mode=True)
    output = capsys.readouterr().out
    assert "_END" in output
    assert "    return 1" in output
    assert "line 12" in output
    assert "line 13" not in output
    assert "... (truncated)" in output
    assert "…" not in output
    assert all(ord(char) < 128 for char in output)


def test_ai_note_prefixes_are_pinned():
    from vericode.llm_explain.explainer import LLM_UNAVAILABLE_PREFIX as exported

    assert LLM_UNAVAILABLE_PREFIX is exported
    assert LLM_UNAVAILABLE_PREFIX == "LLM unavailable, showing static check only"
    assert NOT_REVIEWED_PREFIX == "Not reviewed by the local AI"


def _first_content_line(output: str) -> str:
    for line in output.splitlines():
        if line.strip():
            return line
    return ""


def test_verdict_line_is_first(monkeypatch, capsys):
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)

    _stub_scanners(monkeypatch, [HIGH], ["sample.py"])
    assert main([]) == 1
    blocked = _first_content_line(capsys.readouterr().out)
    assert "VERICODE" in blocked
    assert "Blocked:" in blocked
    assert "1 must-fix" in blocked
    assert "Running 100% on this device" not in blocked

    _stub_scanners(monkeypatch, [MEDIUM], ["app.py"])
    assert main([]) == 0
    warning_out = capsys.readouterr().out
    warning = _first_content_line(warning_out)
    assert "Warning:" in warning
    assert "1 warning" in warning
    assert "Commit allowed. Review the warnings when you can." in warning_out
    assert "Next steps" not in warning_out

    _stub_scanners(monkeypatch, [], ["a.py", "b.py"])
    assert main([]) == 0
    passed_out = capsys.readouterr().out
    passed = _first_content_line(passed_out)
    assert "Passed:" in passed
    assert "2 files checked, no issues" in passed
    assert "Blocked:" not in passed
    assert "Next steps" not in passed_out

    monkeypatch.setenv("VERICODE_OVERRIDE", "1")
    _stub_scanners(monkeypatch, [HIGH], ["sample.py"])
    assert main([]) == 0
    override_out = capsys.readouterr().out
    override = _first_content_line(override_out)
    assert "Warning:" in override
    assert "[ o_O ]" in override or "[ ◉_◉ ]" in override
    assert "OVERRIDE: committing past 1 high-severity issue(s)" in override_out
    assert "Blocked:" not in override

    dismissed = Finding(
        layer="security_scan",
        file="a.py",
        line=1,
        severity="high",
        message="cleared",
        is_real_risk=False,
    )
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    _stub_scanners(monkeypatch, [dismissed], ["a.py"])
    assert main([]) == 0
    cleared = _first_content_line(capsys.readouterr().out)
    assert "Passed:" in cleared
    assert "1 dismissed by local AI" in cleared


def test_checks_strip_reports_ai_status(monkeypatch, capsys):
    reviewed = Finding(
        layer="security_scan",
        file="a.py",
        line=1,
        severity="high",
        message="secret",
        is_real_risk=True,
        explanation="real",
    )
    _stub_scanners(monkeypatch, [reviewed], ["a.py"])
    assert main([]) == 1
    reviewed_out = capsys.readouterr().out
    assert "imports" in reviewed_out
    assert "security" in reviewed_out
    assert "patterns" in reviewed_out
    assert "reviewed 1" in reviewed_out

    unavailable = Finding(
        layer="security_scan",
        file="a.py",
        line=1,
        severity="high",
        message="secret",
        explanation=LLM_UNAVAILABLE_PREFIX + " (Local AI is off. Start it with: ollama serve)",
    )
    _stub_scanners(monkeypatch, [unavailable], ["a.py"])
    assert main([]) == 1
    down = capsys.readouterr().out
    assert "unavailable" in down
    assert "Local AI is off. Start it with: ollama serve" in down
    assert "3) Start the local AI: ollama serve" in down
    assert LLM_UNAVAILABLE_PREFIX not in down
    assert "https://" not in down

    _stub_scanners(monkeypatch, [], ["a.py"])
    assert main([]) == 0
    assert "not needed" in capsys.readouterr().out


def test_code_frame_shows_neighbors_and_skips_bad_files(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    (repo / "app.py").write_text('above\nx = "[red]boom[/]"\nbelow\n', encoding="utf-8")
    (repo / "blob.bin").write_bytes(b"hello\x00BINARY_TOKEN\n")
    subprocess.run(
        ["git", "add", "--", "app.py", "blob.bin"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    monkeypatch.chdir(repo)

    render_report([
        Finding(layer="consistency", file="app.py", line=2, severity="high", message="boom"),
    ], ascii_mode=True)
    framed = capsys.readouterr().out
    assert "above" in framed
    assert 'x = "[red]boom[/]"' in framed
    assert "below" in framed

    render_report([
        Finding(layer="security_scan", file="missing.py", line=1, severity="high", message="gone"),
    ], ascii_mode=True)
    missing = capsys.readouterr().out
    assert "missing.py:1" in missing
    assert "Traceback" not in missing

    render_report([
        Finding(layer="security_scan", file="app.py", line=40, severity="high", message="range"),
    ], ascii_mode=True)
    ranged = capsys.readouterr().out
    assert "above" not in ranged
    assert "[red]" not in ranged

    render_report([
        Finding(layer="security_scan", file="blob.bin", line=1, severity="high", message="binary"),
    ], ascii_mode=True)
    binary = capsys.readouterr().out
    assert "BINARY_TOKEN" not in binary
    assert "hello" not in binary


def test_one_line_patch_is_a_diff(tmp_path, monkeypatch, capsys):
    from rich.console import Console

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    (repo / "app.py").write_text("    token = 'secret'\n", encoding="utf-8")
    subprocess.run(["git", "add", "--", "app.py"], cwd=repo, check=True, capture_output=True)
    monkeypatch.chdir(repo)
    monkeypatch.setattr(
        "vericode.gate.cli._console",
        lambda: Console(highlight=False, width=80, height=30, legacy_windows=False),
    )
    render_report([
        Finding(
            layer="security_scan",
            file="app.py",
            line=1,
            severity="high",
            message="secret",
            fixed_code="    token = os.environ['TOKEN']",
            is_real_risk=True,
        ),
    ], ascii_mode=True)
    output = capsys.readouterr().out
    assert "-     token = 'secret'" in output
    assert "+     token = os.environ['TOKEN']" in output


def test_dismissed_findings_pass_and_stay_below(monkeypatch, capsys):
    dismissed = Finding(
        layer="security_scan",
        file="a.py",
        line=1,
        severity="high",
        message="cleared high",
        is_real_risk=False,
        risk_reasoning="placeholder",
    )
    live = Finding(
        layer="security_scan",
        file="b.py",
        line=2,
        severity="medium",
        message="live medium",
    )
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    _stub_scanners(monkeypatch, [dismissed], ["a.py"])
    assert main([]) == 0
    only = capsys.readouterr().out
    assert "Passed:" in _first_content_line(only)
    assert "Dismissed by local AI (not blocking): 1" in only

    _stub_scanners(monkeypatch, [dismissed, live], ["a.py", "b.py"])
    assert main([]) == 0
    mixed = capsys.readouterr().out
    assert "Warning:" in _first_content_line(mixed)
    assert mixed.index("live medium") < mixed.index("Dismissed by local AI")


def test_ascii_layout_fits_in_80_columns(monkeypatch, capsys):
    finding = Finding(
        layer="security_scan",
        file="app.py",
        line=1,
        severity="high",
        message="plain issue",
        suggested_fix="do this",
        fixed_code="x = 1",
        is_real_risk=True,
        explanation="because",
    )
    _stub_scanners(monkeypatch, [finding], ["app.py"])
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    assert main(["--ascii"]) == 1
    output = capsys.readouterr().out
    assert output
    assert all(ord(char) < 128 for char in output)
    assert len(_first_content_line(output)) <= 80
    assert all(len(line) <= 80 for line in output.splitlines())


def test_color_opt_in_and_no_color(monkeypatch, capsys):
    _stub_scanners(monkeypatch, [HIGH], ["sample.py"])
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    assert main([]) == 1
    assert "\x1b[" not in capsys.readouterr().out

    monkeypatch.setenv("VERICODE_COLOR", "1")
    assert main([]) == 1
    assert "\x1b[" in capsys.readouterr().out

    monkeypatch.setenv("NO_COLOR", "1")
    assert main([]) == 1
    assert "\x1b[" not in capsys.readouterr().out


def test_import_message_shows_the_package_name(capsys):
    name = "definitely_not_a_real_pkg_xyz"
    render_report([
        Finding(
            layer="import_check",
            file="app.py",
            line=1,
            severity="high",
            message=f"'{name}' doesn't match any package on PyPI.",
        ),
    ], ascii_mode=True)
    output = capsys.readouterr().out
    assert name in output
    assert "defi****" not in output


def _fake_token(prefix: str, body: str) -> str:
    return prefix + body


def test_secrets_never_print_a_full_token(tmp_path, monkeypatch, capsys):
    token = _fake_token(
        "ghp_",
        "016C7869F1A2B3C4D5E6F708192A3B4C5D6E7F",
    )
    neighbor = _fake_token(
        "ghp_",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
    sk = _fake_token(
        "sk-",
        "live-ABCDEFGHIJKLMNOP",
    )
    akia = _fake_token(
        "AKIA",
        "IOSFODNN7EXAMPLE",
    )
    xox = _fake_token(
        "xoxb-",
        "123456789012-abcdefghijklmnopqrstuv",
    )
    quoted = "thisisalongquotedstring"
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    (repo / "app.py").write_text(
        f'note = "{quoted}"\nKEY = "{neighbor}"\nTOKEN = "{token}"\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "--", "app.py"], cwd=repo, check=True, capture_output=True)
    monkeypatch.chdir(repo)

    render_report([
        Finding(layer="consistency", file="app.py", line=1, severity="low", message="same shape"),
    ], ascii_mode=True)
    plain = capsys.readouterr().out
    assert f'note = "{quoted}"' in plain
    assert neighbor not in plain
    assert 'KEY = "ghp_****"' in plain

    render_report([
        Finding(
            layer="security_scan",
            file="app.py",
            line=3,
            severity="high",
            message=f"saw {token} {sk} {akia} {xox}",
            explanation=f"model echoed {token}",
            suggested_fix=f"remove {token}",
            fixed_code=f'TOKEN = "{token}"',
            is_real_risk=True,
        ),
    ], ascii_mode=True)
    secret = capsys.readouterr().out
    assert token not in secret
    assert neighbor not in secret
    assert 'TOKEN = "ghp_****"' in secret
    assert 'KEY = "ghp_****"' in secret
    for value in (token, neighbor, sk, akia, xox):
        assert value not in secret
    assert "sk-l****" in secret
    assert "AKIA****" in secret
    assert "xoxb****" in secret


def test_hook_override_lines_fit_in_80_columns(monkeypatch, capsys):
    from rich.console import Console

    def narrow():
        return Console(width=80, height=40, highlight=False, legacy_windows=False)

    _stub_scanners(monkeypatch, [HIGH], ["sample.py"])
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("MSYSTEM", "MINGW64")
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    monkeypatch.setattr("vericode.gate.cli._console", narrow)
    monkeypatch.setattr("vericode.gate.ui._console", narrow)
    assert main(["--ascii"]) == 1
    output = capsys.readouterr().out
    lines = output.splitlines()
    assert all(len(line) <= 80 for line in lines)
    assert any(line.strip() == "VERICODE_OVERRIDE=1 git commit" for line in lines)
    assert any(line.strip() == "$env:VERICODE_OVERRIDE=1; git commit" for line in lines)
    assert not any("VERICODE_OVERRIDE=1 git commit" in line and "$env:" in line for line in lines)


def test_ascii_folds_dashes_quotes_and_ellipsis(capsys):
    message = "wait \u2014 go\u2013on \u2018q\u2019 \u201cQ\u201d end\u2026 \u25cf"
    render_report([
        Finding(layer="security_scan", file="a.py", line=1, severity="medium", message=message),
    ], ascii_mode=True)
    output = capsys.readouterr().out
    assert "wait - go-on 'q' \"Q\" end... ?" in output
    assert all(ord(char) < 128 for char in output)

    render_report([
        Finding(layer="security_scan", file="a.py", line=1, severity="medium", message=message),
    ], ascii_mode=False)
    raw = capsys.readouterr().out
    assert "\u2014" in raw
    assert "\u2026" in raw
