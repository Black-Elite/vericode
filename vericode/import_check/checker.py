"""Layer 1: flags imports of packages that don't exist (hallucinated) or that
exist on PyPI but are obscure and not installed (possible slopsquatting).
No AI. See CLAUDE.md in this folder for the full spec.
"""

from __future__ import annotations

import difflib
import importlib.util
import re
import sys
from functools import lru_cache
from importlib.metadata import packages_distributions
from pathlib import Path

from vericode.import_check.aliases import IMPORT_TO_DIST
from vericode.import_check.imports import parse_imports
from vericode.shared.finding import Finding

DATA_DIR = Path(__file__).parent / "data"


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@lru_cache(maxsize=None)
def _load(filename: str) -> frozenset[str]:
    path = DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"{path} is missing. Run ./setup.sh (needs internet once).")
    return frozenset(path.read_text().split())


def pypi_all() -> frozenset[str]:
    return _load("pypi_all.txt")


def pypi_top() -> frozenset[str]:
    return _load("pypi_top.txt")


@lru_cache(maxsize=None)
def _installed_modules() -> frozenset[str]:
    return frozenset(packages_distributions())


def _is_installed(module: str) -> bool:
    if module in _installed_modules():
        return True
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _is_local(module: str, file_path: Path) -> bool:
    roots = {file_path.resolve().parent, Path.cwd()}
    return any((r / module).is_dir() or (r / f"{module}.py").exists() for r in roots)


def _suggest(dist: str) -> str | None:
    top = pypi_top()
    parts = dist.split("-")
    for i in range(len(parts) - 1, 0, -1):
        prefix = "-".join(parts[:i])
        if prefix in top:
            return prefix
    matches = difflib.get_close_matches(dist, top, n=1, cutoff=0.75)
    return matches[0] if matches else None


def check_module(module: str, file: str, line: int) -> Finding | None:
    if module in sys.stdlib_module_names or module in sys.builtin_module_names:
        return None
    if _is_installed(module) or _is_local(module, Path(file)):
        return None

    dist = normalize(IMPORT_TO_DIST.get(module, module))

    if dist in pypi_top():
        return Finding(
            layer="import_check", file=file, line=line, severity="low",
            message=f"'{module}' is a known package ('{dist}') but isn't installed in this environment.",
            suggested_fix=f"uv add {dist}",
        )

    if dist in pypi_all():
        return Finding(
            layer="import_check", file=file, line=line, severity="medium",
            message=(
                f"'{module}' exists on PyPI but is obscure and not installed. AI tools often "
                f"invent package names that attackers then register (slopsquatting)."
            ),
            suggested_fix=f"Check https://pypi.org/project/{dist}/ (author, age, downloads) before installing.",
        )

    suggestion = _suggest(dist)
    return Finding(
        layer="import_check", file=file, line=line, severity="high",
        message=f"'{module}' doesn't match any package on PyPI. This import is likely hallucinated.",
        suggested_fix=(
            f"Did you mean '{suggestion}'?" if suggestion
            else "Remove this import or replace it with a real package."
        ),
    )


def run(staged_files: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for file in staged_files:
        if not file.endswith(".py"):
            continue
        imports = parse_imports(file)
        if imports is None:
            continue
        for ref in imports:
            finding = check_module(ref.module, file, ref.line)
            if finding:
                findings.append(finding)
    return findings
