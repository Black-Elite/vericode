from vericode.import_check.checker import run


def test_clean_file_returns_no_findings(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("import os\nimport json\n")
    assert run([str(f)]) == []


def test_fake_import_is_flagged(tmp_path):
    f = tmp_path / "bad.py"
    f.write_text("import pandas_fast_reader\n")
    findings = run([str(f)])
    assert len(findings) == 1
    assert findings[0].severity == "high"
