import pytest

from vericode.llm_explain import explainer
from vericode.llm_explain.explainer import enrich, parse_response
from vericode.shared.finding import Finding


def make_finding(path="bad.py", line=2, severity="high") -> Finding:
    return Finding(
        layer="security_scan",
        file=str(path),
        line=line,
        severity=severity,
        message="hardcoded API key",
        suggested_fix="use env var",
    )


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "bad.py"
    p.write_text('import os\nKEY = "sk-123"\nprint(KEY)\n')
    return p


GOOD = (
    '{"is_real_risk": true, "risk_reasoning": "literal secret", '
    '"explanation": "Key is in source.", "fixed_code": "KEY = os.environ[\\"KEY\\"]"}'
)


def test_enrich_fills_fields(monkeypatch, sample):
    prompts = []
    monkeypatch.setattr(explainer, "_chat", lambda p: prompts.append(p) or GOOD)
    [f] = enrich([make_finding(sample)])
    assert f.is_real_risk is True
    assert f.explanation == "Key is in source."
    assert f.fixed_code.startswith("KEY =")
    assert f.severity == "high"
    assert f.suggested_fix == "use env var"  # existing fields preserved
    assert '> 2: KEY = "sk-123"' in prompts[0]  # context with marker


def test_false_positive_downgraded_not_dropped(monkeypatch, sample):
    monkeypatch.setattr(
        explainer, "_chat",
        lambda p: '{"is_real_risk": false, "risk_reasoning": "test fixture", '
                  '"explanation": "Fake.", "fixed_code": ""}',
    )
    result = enrich([make_finding(sample)])
    assert len(result) == 1
    assert result[0].is_real_risk is False
    assert result[0].severity == "low"


def test_json_embedded_in_prose():
    out = parse_response("Sure!\n" + GOOD + "\nHope that helps")
    assert out["is_real_risk"] is True


def test_string_bool_coerced():
    assert parse_response('{"is_real_risk": "false"}')["is_real_risk"] is False


def test_invalid_json_falls_back_to_raw_text(monkeypatch, sample):
    monkeypatch.setattr(explainer, "_chat", lambda p: "this is not json")
    [f] = enrich([make_finding(sample)])
    assert f.explanation == "this is not json"
    assert f.is_real_risk is None
    assert f.severity == "high"


def test_llm_error_never_crashes(monkeypatch, sample):
    def boom(prompt):
        raise TimeoutError("timed out")

    monkeypatch.setattr(explainer, "_chat", boom)
    [f] = enrich([make_finding(sample)])
    assert "LLM unavailable" in f.explanation
    assert f.is_real_risk is None
    assert f.severity == "high"


def test_missing_model_message(monkeypatch):
    class Models:
        models = []

    class Client:
        def list(self):
            return Models()

    monkeypatch.delenv("VERICODE_MODEL", raising=False)
    monkeypatch.setattr(explainer, "_client", lambda: Client())
    explainer.pick_model.cache_clear()
    with pytest.raises(RuntimeError, match="ollama pull"):
        explainer.pick_model()
    explainer.pick_model.cache_clear()


def test_fallback_to_3b(monkeypatch):
    class M:
        model = "qwen2.5-coder:3b"

    class Models:
        models = [M()]

    class Client:
        def list(self):
            return Models()

    monkeypatch.delenv("VERICODE_MODEL", raising=False)
    monkeypatch.setattr(explainer, "_client", lambda: Client())
    explainer.pick_model.cache_clear()
    assert explainer.pick_model() == "qwen2.5-coder:3b"
    explainer.pick_model.cache_clear()


def test_missing_source_file_still_works(monkeypatch):
    monkeypatch.setattr(explainer, "_chat", lambda p: GOOD)
    [f] = enrich([make_finding("nope.py")])
    assert f.is_real_risk is True


def test_empty_list():
    assert enrich([]) == []
