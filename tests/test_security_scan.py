import pytest

from vericode.security_scan.scanner import DATA_DIR, run

pytestmark = pytest.mark.skipif(
    not (DATA_DIR / "secrets.yml").exists(),
    reason="Semgrep rules missing; run ./setup.sh",
)

SECRET = "ghp_016C7869F1A2B3C4D5E6F708192A3B4C5D6E7F"


def scan(tmp_path, source, name="sample.py"):
    f = tmp_path / name
    f.write_text(source)
    return run([str(f)])


def test_hardcoded_secret_is_flagged_high(tmp_path):
    [finding] = scan(tmp_path, f'TOKEN = "{SECRET}"\n')
    assert finding.severity == "high"
    assert finding.line == 1


def test_secret_value_never_leaks_into_a_finding(tmp_path):
    findings = scan(tmp_path, f'TOKEN = "{SECRET}"\n')
    assert findings
    assert all(SECRET not in repr(f) for f in findings)


def test_unsafe_system_call_is_flagged(tmp_path):
    [finding] = scan(tmp_path, "import os\n\n\ndef handle(cmd):\n    os.system(cmd)\n")
    assert finding.line == 5


def test_clean_file_returns_no_findings(tmp_path):
    assert scan(tmp_path, "def add(a, b):\n    return a + b\n") == []


def test_secrets_outside_python_files_are_flagged(tmp_path):
    [finding] = scan(tmp_path, f"GITHUB_TOKEN={SECRET}\n", name=".env")
    assert finding.severity == "high"


def test_one_finding_per_line_when_both_scanners_match(tmp_path):
    findings = scan(tmp_path, f'TOKEN = "{SECRET}"\n')
    lines = [f.line for f in findings]
    assert len(lines) == len(set(lines))


def test_binary_and_missing_files_do_not_crash(tmp_path):
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\x00\xff\xfe")
    assert run([str(binary), str(tmp_path / "gone.py")]) == []
