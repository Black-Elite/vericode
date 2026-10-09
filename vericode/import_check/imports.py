"""Extracts absolute top-level imports from a Python file."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ImportRef:
    module: str  # top-level name only: "pandas" for "pandas.io.json"
    line: int


def parse_imports(path: str | Path) -> list[ImportRef] | None:
    """Returns one ImportRef per distinct top-level module (first occurrence),
    skipping relative imports. Returns None if the file can't be parsed.
    """
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return None

    seen: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        else:
            continue
        for name in names:
            top = name.split(".")[0]
            if top not in seen or node.lineno < seen[top]:
                seen[top] = node.lineno

    return [ImportRef(module=m, line=l) for m, l in sorted(seen.items(), key=lambda kv: kv[1])]
