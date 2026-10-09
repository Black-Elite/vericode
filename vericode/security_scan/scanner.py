"""Layer 2: wraps Semgrep's offline rulesets for secrets/injection risks. No
custom AI. See CLAUDE.md in this folder for the full spec.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

from vericode.shared.finding import Finding, Severity

DATA_DIR = Path(__file__).parent / "data"
RULE_FILES = ("secrets.yml", "security-audit.yml", "system-call.yml")
SEMGREP_TIMEOUT = 60


@lru_cache(maxsize=None)
def _rule_files() -> tuple[str, ...]:
    paths = []
    for name in RULE_FILES:
        path = DATA_DIR / name
        if not path.exists():
            raise FileNotFoundError(f"{path} is missing. Run ./setup.sh (needs internet once).")
        paths.append(str(path))
    return tuple(paths)


def _skipped(scanner: str, reason: str) -> None:
    print(f"vericode: {scanner} scan skipped ({reason}).", file=sys.stderr)


def _severity(semgrep_severity: str, confidence: str | None) -> Severity:
    level: Severity = {"ERROR": "high", "WARNING": "medium"}.get(semgrep_severity, "low")
    if confidence == "LOW":
        level = {"high": "medium", "medium": "low"}.get(level, "low")
    return level


def _semgrep(files: list[str]) -> list[Finding]:
    binary = shutil.which("semgrep")
    argv = [binary] if binary else [sys.executable, "-m", "semgrep"]
    argv += ["scan", "--json", "--metrics=off", "--disable-version-check", "--quiet"]
    for rules in _rule_files():
        argv += ["--config", rules]

    try:
        # semgrep exits 1 on findings, so check=True would be wrong
        proc = subprocess.run(argv + files, capture_output=True, text=True, timeout=SEMGREP_TIMEOUT)
        if proc.returncode > 1:
            _skipped("semgrep", f"exit {proc.returncode}")
            return []
        results = json.loads(proc.stdout)["results"]
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError) as exc:
        _skipped("semgrep", str(exc))
        return []

    findings = []
    for result in results:
        extra = result["extra"]
        # extra["lines"] is the raw matched source — keep it out of Finding
        findings.append(Finding(
            layer="security_scan",
            file=result["path"],
            line=result["start"]["line"],
            severity=_severity(extra["severity"], extra.get("metadata", {}).get("confidence")),
            message=extra["message"].strip(),
            suggested_fix=f"Review {result['check_id'].split('.')[-1]} at this line before committing.",
        ))
    return findings


def _betterleaks(files: list[str]) -> list[Finding]:
    try:
        from pybetterleaks import scan_text
    except ImportError:
        _skipped("betterleaks", "not installed")
        return []

    findings = []
    for file in files:
        try:
            # validation=True would upload the secret to vendor APIs
            result = scan_text(Path(file).read_text(encoding="utf-8"), validation=False)
        except (OSError, UnicodeDecodeError):
            continue
        for leak in result.findings:
            findings.append(Finding(
                layer="security_scan",
                file=file,
                line=leak.line + 1,  # betterleaks counts from 0
                severity="high",
                message=(
                    f"{leak.description} A credential committed to Git stays in its history "
                    f"forever, even if a later commit deletes the line."
                ),
                suggested_fix="Move it to an environment variable, then rotate it — assume it is already leaked.",
            ))
    return findings


def run(staged_files: list[str]) -> list[Finding]:
    """Run semgrep --config <cached rules> --json against staged_files only,
    and map its output into Findings.
    """
    files = [f for f in staged_files if Path(f).is_file()]
    if not files:
        return []

    findings: list[Finding] = []
    seen = set()
    for finding in _betterleaks(files) + _semgrep(files):
        key = (finding.file, finding.line)
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)
    return findings
