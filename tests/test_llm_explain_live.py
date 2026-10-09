"""Runs Layer 3 against the real local model. Skipped when Ollama isn't
running or no Qwen2.5-Coder model is pulled. Run only these with:
    uv run pytest -m live
"""

import time

import pytest

from vericode.llm_explain import explainer
from vericode.llm_explain.explainer import enrich
from vericode.shared.finding import Finding

pytestmark = pytest.mark.live

SECRET = "AKIAIOSFODNN7EXAMPLE9"


@pytest.fixture(scope="module", autouse=True)
def require_model():
    explainer.pick_model.cache_clear()
    try:
        model = explainer.pick_model()
    except Exception as exc:
        pytest.skip(f"local model unavailable: {exc}")
    print(f"\nusing model: {model}")
    yield
    explainer.pick_model.cache_clear()


def enrich_file(tmp_path, source, line, message):
    path = tmp_path / "app.py"
    path.write_text(source)
    finding = Finding(layer="security_scan", file=str(path), line=line, severity="high", message=message)
    start = time.perf_counter()
    [result] = enrich([finding])
    print(f"{message!r}: {time.perf_counter() - start:.1f}s -> is_real_risk={result.is_real_risk}")
    return result


def test_real_secret_is_judged_real_with_a_code_fix(tmp_path):
    source = (
        "import boto3\n"
        f'AWS_KEY = "{SECRET}"\n'
        "client = boto3.client('s3', aws_access_key_id=AWS_KEY)\n"
    )
    f = enrich_file(tmp_path, source, 2, "Hardcoded AWS access key")

    assert not f.explanation.startswith("LLM unavailable"), f.explanation
    assert f.is_real_risk is True
    assert f.severity == "high"
    assert f.fixed_code
    assert SECRET not in f.fixed_code


def test_placeholder_secret_is_judged_false_positive(tmp_path):
    source = (
        "# Example config for the README. Users replace this value.\n"
        'API_KEY = "your-api-key-here"\n'
    )
    f = enrich_file(tmp_path, source, 2, "Hardcoded API key")

    assert not f.explanation.startswith("LLM unavailable"), f.explanation
    assert f.is_real_risk is False
    assert f.severity == "low"


def test_command_injection_is_judged_real(tmp_path):
    source = (
        "import os\n"
        "from flask import request\n\n"
        "def ping():\n"
        "    host = request.args['host']\n"
        "    os.system('ping -c 1 ' + host)\n"
    )
    f = enrich_file(tmp_path, source, 6, "os.system called with user-controlled input")

    assert not f.explanation.startswith("LLM unavailable"), f.explanation
    assert f.is_real_risk is True
    assert f.fixed_code
