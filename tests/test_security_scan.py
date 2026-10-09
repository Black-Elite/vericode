from vericode.security_scan.scanner import run


def test_hardcoded_secret_is_flagged(tmp_path):
    f = tmp_path / "bad.py"
    f.write_text('API_KEY = "sk-abcdef1234567890"\n')
    findings = run([str(f)])
    assert len(findings) >= 1


def test_clean_file_returns_no_findings(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("def add(a, b):\n    return a + b\n")
    assert run([str(f)]) == []
