"""Layer 2: flags hardcoded secrets and unsafe calls in staged files. No custom
AI. See CLAUDE.md in this folder for the full spec.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

from vericode.shared.finding import Finding, Severity

DATA_DIR = Path(__file__).parent / "data"
SEMGREP_TIMEOUT = 60
MAX_BYTES = 1_000_000  # semgrep's own default cap


@lru_cache(maxsize=None)
def _rule_file() -> str:
    path = DATA_DIR / "rules.yml"
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing. Run ./setup.sh (needs internet once).")
    return str(path)


def _skipped(scanner: str, reason: str) -> None:
    print(f"vericode: {scanner} scan skipped ({reason}).", file=sys.stderr)


def _call_name(call: ast.Call) -> str:
    parts, node = [], call.func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _unsafe_call(call: ast.Call) -> str:
    name = _call_name(call)
    if name in ("eval", "exec"):
        return f"{name}()"
    if name == "os.system":
        return "os.system()"
    if name.startswith("subprocess."):
        for kw in call.keywords:
            if kw.arg == "shell" and getattr(kw.value, "value", False) is True:
                return f"{name}(shell=True)"
    return ""


def _ast_scan(files: list[str]) -> list[Finding]:
    findings = []
    for file in files:
        if not file.endswith(".py"):
            continue
        try:
            tree = ast.parse(Path(file).read_text(encoding="utf-8"), filename=file)
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            what = _unsafe_call(node)
            if not what:
                continue
            # a literal argument can't be attacker-controlled
            literal = all(isinstance(a, ast.Constant) for a in node.args) and bool(node.args)
            findings.append(Finding(
                layer="security_scan",
                file=file,
                line=node.lineno,
                severity="medium" if literal else "high",
                message=(
                    f"{what} runs whatever it is given. If any part of that value comes from "
                    f"user input, a request, or a file, this is remote code execution."
                ),
                suggested_fix=f"Replace {what} with an explicit call that cannot run arbitrary code.",
            ))
    return findings


def _severity(semgrep_severity: str, confidence: str | None) -> Severity:
    level: Severity = {"ERROR": "high", "WARNING": "medium"}.get(semgrep_severity, "low")
    if confidence == "LOW":
        level = {"high": "medium", "medium": "low"}.get(level, "low")
    return level


def _semgrep(files: list[str]) -> list[Finding]:
    binary = shutil.which("semgrep")
    argv = [binary] if binary else [sys.executable, "-m", "semgrep"]
    argv += ["scan", "--json", "--metrics=off", "--disable-version-check", "--quiet"]
    argv += ["--config", _rule_file()]

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
                line=(leak.line or 0) + 1,  # counts from 0, and omits the 0
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
    files = []
    for file in staged_files:
        path = Path(file)
        if not path.is_file():
            continue
        if path.stat().st_size > MAX_BYTES:
            _skipped(file, f"over {MAX_BYTES // 1000}kB")
            continue
        files.append(file)
    if not files:
        return []

    # semgrep costs ~3s per run against ~50ms for the rest, so it's opt-in
    scanned = _betterleaks(files) + _ast_scan(files)
    if os.environ.get("VERICODE_SEMGREP"):
        scanned += _semgrep(files)

    findings: list[Finding] = []
    seen = set()
    for finding in scanned:
        key = (finding.file, finding.line)
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)
    return findings
