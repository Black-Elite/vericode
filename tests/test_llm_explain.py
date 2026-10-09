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


DISMISS = '{"reason": "No outside input reaches it.", "is_real_risk": false, "fix": ""}'


def test_false_positive_with_supporting_evidence_is_downgraded_not_dropped(monkeypatch, tmp_path):
    src = tmp_path / "tools.py"
    src.write_text("import subprocess\n\nsubprocess.run('git status', shell=True)\n")
    monkeypatch.setattr(explainer, "_chat", lambda p: DISMISS)
    result = enrich([make_finding(src, line=3)])
    assert len(result) == 1
    assert result[0].is_real_risk is False
    assert result[0].severity == "low"


def test_ai_cannot_dismiss_a_real_looking_secret(monkeypatch, sample):
    monkeypatch.setattr(explainer, "_chat", lambda p: DISMISS)
    [f] = enrich([make_finding(sample)])
    assert f.is_real_risk is None  # gate still treats it as real
    assert f.severity == "high"
    assert "still counts" in f.explanation


def test_prompt_includes_static_evidence(monkeypatch, tmp_path):
    src = tmp_path / "ping.py"
    src.write_text("import os\nimport sys\n\nos.system('ping ' + sys.argv[1])\n")
    prompts = []
    monkeypatch.setattr(explainer, "_chat", lambda p: prompts.append(p) or GOOD)
    enrich([make_finding(src, line=4)])
    assert "Static analysis found: Outside input reaches this call" in prompts[0]
    assert "sys.argv" in prompts[0]


def test_reason_first_answer_is_parsed():
    out = parse_response('{"reason": "user input", "is_real_risk": true, "fix": "subprocess.run([...])"}')
    assert out["is_real_risk"] is True
    assert out["risk_reasoning"] == out["explanation"] == "user input"
    assert out["fixed_code"] == "subprocess.run([...])"


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


@pytest.mark.parametrize("raw, expected", [("45", 45.0), ("2.5", 2.5), ("slow", 30.0), ("0", 30.0)])
def test_timeout_setting(monkeypatch, raw, expected):
    monkeypatch.setenv("VERICODE_TIMEOUT", raw)
    assert explainer.timeout_seconds() == expected


def test_client_uses_timeout_setting(monkeypatch):
    seen = {}

    class FakeClient:
        def __init__(self, timeout):
            seen["timeout"] = timeout

    monkeypatch.setenv("VERICODE_TIMEOUT", "45")
    monkeypatch.setattr(explainer.ollama, "Client", FakeClient)
    explainer._client()
    assert seen["timeout"] == 45.0


def test_only_most_severe_findings_go_to_the_ai(monkeypatch, sample):
    calls = []
    monkeypatch.delenv("VERICODE_MAX_AI_FINDINGS", raising=False)
    monkeypatch.setattr(explainer, "_chat", lambda p: calls.append(p) or GOOD)
    findings = [
        make_finding(sample, severity=s) for s in ("low", "high", "medium", "high", "medium")
    ]
    result = enrich(findings)

    assert len(calls) == 3
    assert result == findings  # original order kept
    reviewed = [f for f in result if f.is_real_risk is not None]
    assert sorted(f.severity for f in reviewed) == ["high", "high", "medium"]
    skipped = [f for f in result if f.is_real_risk is None]
    assert all("Not reviewed by the local AI" in f.explanation for f in skipped)


def test_unreviewed_high_finding_still_blocks(monkeypatch, sample):
    monkeypatch.setenv("VERICODE_MAX_AI_FINDINGS", "1")
    monkeypatch.setattr(explainer, "_chat", lambda p: GOOD)
    [first, second] = enrich([make_finding(sample), make_finding(sample)])
    assert first.is_real_risk is True
    assert second.is_real_risk is None  # gate treats None as real
    assert second.severity == "high"


@pytest.mark.parametrize("raw, expected", [("5", 5), ("abc", 3), ("0", 3), ("-2", 3)])
def test_max_ai_findings_setting(monkeypatch, raw, expected):
    monkeypatch.setenv("VERICODE_MAX_AI_FINDINGS", raw)
    assert explainer.max_ai_findings() == expected


SLACK = "xoxb-1234567890-abcdefghijkl"


@pytest.mark.parametrize(
    "text",
    [
        f'SLACK_TOKEN = "{SLACK}"',
        f"client = WebClient('{SLACK}')",
        'password = "hunter2hunter2"',
        'headers = {"Authorization": "Bearer abcdefghijklmnop1234"}',
        'AWS = "AKIAIOSFODNN7EXAMPLE"',
    ],
)
def test_redact_blanks_secret_values(text):
    out = explainer.redact(text)
    assert explainer.REDACTED in out
    for secret in (SLACK, "hunter2hunter2", "abcdefghijklmnop1234", "AKIAIOSFODNN7EXAMPLE"):
        assert secret not in out


def test_redact_keeps_names_and_clean_code():
    assert explainer.redact('SLACK_TOKEN = "<REDACTED>"') == 'SLACK_TOKEN = "<REDACTED>"'
    clean = 'import os\ntoken = os.environ["SLACK_TOKEN"]'
    assert explainer.redact(clean) == clean


def test_secret_never_reaches_prompt_or_output(monkeypatch, tmp_path):
    src = tmp_path / "slack.py"
    src.write_text(f'import os\nSLACK_TOKEN = "{SLACK}"\n')
    prompts = []
    leaky = (
        '{"is_real_risk": true, "risk_reasoning": "token ' + SLACK + ' is hardcoded", '
        '"explanation": "Remove it.", "fixed_code": "SLACK_TOKEN = \\"' + SLACK + '\\""}'
    )
    monkeypatch.setattr(explainer, "_chat", lambda p: prompts.append(p) or leaky)
    f = make_finding(src)
    f.message = f"Slack token {SLACK} found"
    [r] = enrich([f])
    assert SLACK not in prompts[0]
    assert SLACK not in (r.fixed_code + r.risk_reasoning + r.explanation)
    assert r.is_real_risk is True  # verdict still set


def test_import_check_suggestion_not_overridden(monkeypatch, tmp_path):
    src = tmp_path / "a.py"
    src.write_text("import markdown_pdf_x\n")
    monkeypatch.setattr(explainer, "_chat", lambda p: GOOD)
    f = Finding(
        layer="import_check", file=str(src), line=1, severity="high",
        message="package does not exist", suggested_fix="Did you mean markdown-pdf?",
    )
    [r] = enrich([f])
    assert r.suggested_fix == "Did you mean markdown-pdf?"
    assert r.fixed_code is None
    assert r.is_real_risk is True
