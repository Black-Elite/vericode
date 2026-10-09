import pytest

from vericode.import_check.checker import DATA_DIR, run

pytestmark = pytest.mark.skipif(
    not (DATA_DIR / "pypi_all.txt").exists(),
    reason="PyPI snapshot missing; run ./setup.sh",
)


def check(tmp_path, source, name="sample.py"):
    f = tmp_path / name
    f.write_text(source)
    return run([str(f)])


def test_clean_file_returns_no_findings(tmp_path):
    assert check(tmp_path, "import os\nimport json\nfrom collections import abc\n") == []


def test_fake_import_is_flagged_high_with_suggestion(tmp_path):
    [finding] = check(tmp_path, "import pandas_fast_reader\n")
    assert finding.severity == "high"
    assert finding.line == 1
    assert "pandas" in finding.suggested_fix


def test_typo_import_suggests_real_package(tmp_path):
    [finding] = check(tmp_path, "import reqeusts\n")
    assert finding.severity == "high"
    assert "requests" in finding.suggested_fix


def test_installed_package_is_clean(tmp_path):
    assert check(tmp_path, "import rich\nfrom rich.console import Console\n") == []


def test_import_name_differing_from_dist_name_is_not_hallucinated(tmp_path):
    findings = check(tmp_path, "import cv2\nimport sklearn\nfrom PIL import Image\n")
    assert all(f.severity != "high" for f in findings)


def test_obscure_pypi_package_is_flagged_medium(tmp_path):
    [finding] = check(tmp_path, "from flask_jwt_simple import create_jwt\n")
    assert finding.severity == "medium"


def test_relative_and_local_imports_are_skipped(tmp_path):
    (tmp_path / "helpers.py").write_text("X = 1\n")
    assert check(tmp_path, "from . import sibling\nfrom .pkg import thing\nimport helpers\n") == []


def test_unparseable_file_does_not_crash(tmp_path):
    assert check(tmp_path, "def broken(:\n") == []


def test_non_python_files_are_ignored(tmp_path):
    assert check(tmp_path, "import pandas_fast_reader\n", name="notes.txt") == []
