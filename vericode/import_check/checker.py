"""Layer 1: flags imports of packages that don't exist. No AI. See CLAUDE.md
in this folder for the full spec.
"""

from __future__ import annotations

from vericode.shared.finding import Finding


def run(staged_files: list[str]) -> list[Finding]:
    """Scan staged_files for imports that don't resolve to stdlib, an
    installed package, or the offline PyPI snapshot. Returns Findings for
    anything that doesn't resolve.
    """
    findings: list[Finding] = []
    # TODO: ast.walk each file, check sys.stdlib_module_names ->
    # importlib.util.find_spec -> offline snapshot, fuzzy-match on miss.
    return findings
