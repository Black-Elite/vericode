from vericode.gate import cli
from vericode.shared.finding import Finding

DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -3 +3 @@
+import nope
@@ -10,0 +11,2 @@
+token = "sk-live-123"
+eval(user_input)
diff --git a/clean.py b/clean.py
--- /dev/null
+++ b/clean.py
@@ -0,0 +1 @@
+import os
"""


def test_parse_added_lines_handles_single_and_multi_line_hunks():
    assert cli.parse_added_lines(DIFF) == {"app.py": {3, 11, 12}, "clean.py": {1}}


def finding(severity="high", line=1, is_real_risk=None):
    return Finding(
        layer="security_scan", file="app.py", line=line,
        severity=severity, message="hardcoded secret", is_real_risk=is_real_risk,
    )


def gate(monkeypatch, findings, override=None):
    monkeypatch.setattr(cli, "get_staged_files", lambda: ["app.py"])
    monkeypatch.setattr(cli, "added_lines", lambda: {"app.py": {1}})
    monkeypatch.setattr(cli, "run_import_check", lambda files: [])
    monkeypatch.setattr(cli, "run_security_scan", lambda files: findings)
    monkeypatch.setattr(cli, "enrich", lambda fs: fs)
    monkeypatch.delenv("VERICODE_OVERRIDE", raising=False)
    if override is not None:
        monkeypatch.setenv("VERICODE_OVERRIDE", override)
    return cli.main()


def test_clean_commit_passes(monkeypatch):
    assert gate(monkeypatch, []) == 0


def test_high_severity_blocks(monkeypatch):
    assert gate(monkeypatch, [finding()]) == 1


def test_medium_severity_does_not_block(monkeypatch):
    assert gate(monkeypatch, [finding(severity="medium")]) == 0


def test_ai_false_positive_does_not_block(monkeypatch):
    assert gate(monkeypatch, [finding(is_real_risk=False)]) == 0


def test_override_allows_commit(monkeypatch):
    assert gate(monkeypatch, [finding()], override="1") == 0


def test_findings_outside_the_diff_are_ignored(monkeypatch):
    assert gate(monkeypatch, [finding(line=99)]) == 0
