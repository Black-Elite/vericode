"""Consistency layer: checks new code against the rest of the codebase. No AI.

1. Missing pattern: if most sibling handlers (same decorator) run a guard such
   as check_owner() or raise PermissionError and a new one doesn't, flag it.
   "Bugs as Deviant Behavior" (Engler et al., 2001): the majority is probably
   right. Layer 3 then judges the finding and writes the fix.
2. Duplicate: a function whose structure matches an existing one, ignoring
   names, should reuse it instead.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from vericode.shared.finding import Finding

MIN_SIBLINGS = 3
MAJORITY = 0.75
MIN_DUPLICATE_STATEMENTS = 3
MAX_REPO_FILES = 2000
GUARD_WORDS = re.compile(
    r"(?i)(owner|auth|permission|forbid|login|access|admin|role|csrf|verify|validate|require|allow|check)"
)


@dataclass
class FunctionInfo:
    file: str  # as passed in for staged files; absolute for the rest of the repo
    name: str
    line: int
    decorators: frozenset[str]
    guards: dict[str, str] = field(default_factory=dict)  # feature -> example source
    shape: str | None = None  # structural hash of the body, None if too short


def run(staged_files: list[str]) -> list[Finding]:
    staged = [f for f in staged_files if f.endswith(".py") and Path(f).is_file()]
    if not staged:
        return []
    staged_keys = {_key(f) for f in staged}
    new_functions = [fn for f in staged for fn in _functions(f)]
    existing = [
        fn for f in _repo_python_files(staged) if _key(f) not in staged_keys for fn in _functions(f)
    ]
    findings = []
    for fn in new_functions:
        others = existing + [o for o in new_functions if o is not fn]
        missing = _missing_guard(fn, others)
        if missing:
            findings.append(missing)
        duplicate = _duplicate(fn, existing)
        if duplicate:
            findings.append(duplicate)
    return findings


def _key(path: str) -> str:
    return str(Path(path).resolve())


def _repo_python_files(staged: list[str]) -> list[str]:
    """Every tracked .py file in the repo; falls back to the staged files' folders."""
    try:
        top = subprocess.run(
            ["git", "-C", str(Path(staged[0]).resolve().parent), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True, encoding="utf-8",
        ).stdout.strip()
        listed = subprocess.run(
            ["git", "-C", top, "ls-files", "--", "*.py"],
            capture_output=True, text=True, check=True, encoding="utf-8",
        ).stdout.split("\n")
        files = [str(Path(top) / name) for name in listed if name]
    except (OSError, subprocess.CalledProcessError):
        folders = {Path(f).resolve().parent for f in staged}
        files = [str(p) for d in folders for p in d.glob("*.py")]
    return files[:MAX_REPO_FILES]


def _functions(path: str) -> list[FunctionInfo]:
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=path)
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(FunctionInfo(
                file=path,
                name=node.name,
                line=node.lineno,
                decorators=frozenset(_dotted(d) for d in node.decorator_list),
                guards=_guards(node),
                shape=_shape(node),
            ))
    return out


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _guards(fn: ast.AST) -> dict[str, str]:
    """Guard-like calls and raised exceptions in a function, with an example of each."""
    found: dict[str, str] = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = _dotted(node)
            if name and GUARD_WORDS.search(name):
                found.setdefault(f"call {name}()", ast.unparse(node))
        elif isinstance(node, ast.Raise) and node.exc is not None:
            name = _dotted(node.exc)
            # only access-control errors: a shared `raise NotFound` isn't a guard
            if name and GUARD_WORDS.search(name):
                found.setdefault(f"raise {name}", ast.unparse(node))
    return found


class _Anonymize(ast.NodeTransformer):
    def visit_Name(self, node):
        return ast.copy_location(ast.Name(id="_", ctx=node.ctx), node)

    def visit_arg(self, node):
        node.arg = "_"
        node.annotation = None
        return node


def _shape(fn: ast.AST) -> str | None:
    body = [s for s in fn.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
    if len(body) < MIN_DUPLICATE_STATEMENTS:
        return None
    anon = [_Anonymize().visit(copy.deepcopy(s)) for s in body]
    return hashlib.sha1("\n".join(ast.dump(s) for s in anon).encode()).hexdigest()


def _missing_guard(fn: FunctionInfo, others: list[FunctionInfo]) -> Finding | None:
    if not fn.decorators:
        return None
    siblings = [o for o in others if o.decorators & fn.decorators]
    if len(siblings) < MIN_SIBLINGS:
        return None
    best = None
    for feature in {f for s in siblings for f in s.guards}:
        if feature in fn.guards:
            continue
        having = [s for s in siblings if feature in s.guards]
        if len(having) / len(siblings) >= MAJORITY and (best is None or len(having) > len(best[1])):
            best = (feature, having)
    if best is None:
        return None
    feature, having = best
    example = having[0]
    decorator = sorted(fn.decorators & example.decorators)[0]
    is_raise = feature.startswith("raise ")
    action = (f"raise {feature[6:]}" if is_raise else f"call {feature[5:]}") + " before acting"
    return Finding(
        layer="consistency",
        file=fn.file,
        line=fn.line,
        severity="high",
        message=(
            f"{len(having)} of {len(siblings)} similar @{decorator} handlers {action}; "
            f"{fn.name} doesn't. Example from {example.name} "
            f"({Path(example.file).name}:{example.line}): {example.guards[feature]}"
        ),
        suggested_fix=f"Add the same check as {example.name}: {example.guards[feature]}",
    )


def _duplicate(fn: FunctionInfo, existing: list[FunctionInfo]) -> Finding | None:
    if fn.shape is None:
        return None
    for other in existing:
        if other.shape == fn.shape:
            return Finding(
                layer="consistency",
                file=fn.file,
                line=fn.line,
                severity="low",
                message=(
                    f"{fn.name} has the same logic as {other.name} "
                    f"({Path(other.file).name}:{other.line}), only with different names."
                ),
                suggested_fix=f"Reuse {other.name} instead of keeping two copies.",
            )
    return None
