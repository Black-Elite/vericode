from vericode.llm_explain.explainer import enrich
from vericode.shared.finding import Finding


def test_enrich_fills_in_fields():
    finding = Finding(
        layer="security_scan",
        file="bad.py",
        line=1,
        severity="high",
        message="hardcoded API key",
    )
    [enriched] = enrich([finding])
    assert enriched.explanation is not None
    assert enriched.is_real_risk is not None
