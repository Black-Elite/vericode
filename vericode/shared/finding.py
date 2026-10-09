"""The shared contract. Every layer returns a list of these. Don't change the
shape without telling the team — the gate (vericode/gate/cli.py) imports all
three layers directly and depends on this exact structure.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Literal, Optional

Severity = Literal["high", "medium", "low"]
Layer = Literal["import_check", "security_scan", "llm_explain", "consistency"]


@dataclass
class Finding:
    layer: Layer
    file: str
    line: int
    severity: Severity
    message: str
    suggested_fix: Optional[str] = None

    # Filled in later by llm_explain.enrich(), left None until then.
    is_real_risk: Optional[bool] = None
    risk_reasoning: Optional[str] = None
    explanation: Optional[str] = None
    fixed_code: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
