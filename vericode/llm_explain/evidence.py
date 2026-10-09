"""Static facts about a flagged line, computed with ast and no AI.

The local model reasons over these facts instead of guessing from raw code,
and an AI "false alarm" verdict is only trusted when the facts support it.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from vericode.shared.finding import Finding

OUTSIDE_SOURCES = {
    "sys.argv": "command-line input",
    "input": "user input",
    "request": "web request input",
    "flask.request": "web request input",
    "os.environ": "an environment variable",
    "os.getenv": "an environment variable",
    "open": "file contents",
    "socket": "network data",
}
PROGRAM_SOURCES = ("date.", "datetime.", "time.", "uuid.", "random.", "len", "str", "int")
RISKY_CALLS = {"eval", "exec", "os.system", "os.popen"}
PLACEHOLDER = re.compile(
    r"(?i)(your[-_ ]|[-_ ]here\b|changeme|change[-_]me|example|placeholder|dummy|xxx|<[^>]+>|replace[-_ ]?me|todo)"
)
STRING_LITERAL = re.compile(r"""(["'])([^"'\n]*)\1""")
MAX_TRACE_DEPTH = 2


@dataclass
class Evidence:
    text: str | None  # one line for the prompt, or None when there's nothing to add
    supports_dismissal: bool  # may an AI "false alarm" verdict lower this finding?


def gather(finding: Finding) -> Evidence:
    """Never raises: unreadable or unparsable files just yield no evidence."""
    if finding.layer == "import_check":
        # Layer 1 already states the fact (not on PyPI / obscure); never cleared by the AI.
        return Evidence(None, False)
    try:
        source = Path(finding.file).read_text(encoding="utf-8")
    except OSError:
        return Evidence(None, False)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None

    if tree is not None:
        call = _risky_call_at(tree, finding.line)
        if call is not None:
            return _call_evidence(tree, call)

    lines = source.splitlines()
    line = lines[finding.line - 1] if 0 < finding.line <= len(lines) else ""
    return _secret_evidence(line)


def _dotted(node: ast.AST) -> str:
    parts = []
    while True:
        if isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Subscript):
            node = node.value
        elif isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        else:
            return ".".join(reversed(parts))


def _call_name(call: ast.Call) -> str:
    return _dotted(call.func)


def _is_risky(call: ast.Call) -> bool:
    name = _call_name(call)
    if name in RISKY_CALLS:
        return True
    return name.startswith("subprocess.") and any(
        kw.arg == "shell" and getattr(kw.value, "value", False) is True for kw in call.keywords
    )


def _risky_call_at(tree: ast.AST, line: int) -> ast.Call | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_risky(node):
            if node.lineno <= line <= getattr(node, "end_lineno", node.lineno):
                return node
    return None


def _operands(expr: ast.AST) -> list[ast.AST]:
    """Split string building ("a" + x, f"{x}", "%s" % x) into the values that feed it."""
    if isinstance(expr, ast.BinOp):
        return _operands(expr.left) + _operands(expr.right)
    if isinstance(expr, ast.JoinedStr):
        return [v for part in expr.values for v in _operands(part)]
    if isinstance(expr, ast.FormattedValue):
        return _operands(expr.value)
    if isinstance(expr, (ast.List, ast.Tuple)):
        return [v for elt in expr.elts for v in _operands(elt)]
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr in (
        "format", "join", "strip", "lower", "upper",
    ):
        base = _operands(expr.func.value)
        return base + [v for a in expr.args for v in _operands(a)]
    return [expr]


def _enclosing_function(tree: ast.AST, target: ast.AST) -> ast.FunctionDef | None:
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= target.lineno <= getattr(node, "end_lineno", node.lineno):
                if best is None or node.lineno > best.lineno:
                    best = node
    return best


def _classify(tree: ast.AST, expr: ast.AST, scope: ast.AST | None, depth: int) -> tuple[str, str]:
    """Returns (kind, description); kind is 'fixed', 'program', 'outside' or 'unknown'."""
    if isinstance(expr, ast.Constant):
        return "fixed", repr(expr.value)
    if isinstance(expr, ast.Name):
        return _trace_name(tree, expr.id, scope, depth)
    name = _dotted(expr)
    for prefix, label in OUTSIDE_SOURCES.items():
        if name == prefix or name.startswith(prefix + "."):
            return "outside", f"{name} ({label})"
    if name.startswith(PROGRAM_SOURCES) or name in PROGRAM_SOURCES:
        return "program", f"{name}() (generated by the program)"
    base = name.split(".")[0]
    if base and isinstance(expr, (ast.Attribute, ast.Subscript, ast.Call)):
        return _trace_name(tree, base, scope, depth)
    return "unknown", ast.unparse(expr)


def _trace_name(tree: ast.AST, name: str, scope: ast.AST | None, depth: int) -> tuple[str, str]:
    if depth > MAX_TRACE_DEPTH:
        return "unknown", f"`{name}`"
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        params = [a.arg for a in scope.args.args]
        if name in params:
            index = params.index(name)
            sources = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and _call_name(node) == scope.name and len(node.args) > index:
                    sources.append(_classify(tree, node.args[index], _enclosing_function(tree, node), depth + 1))
            if not sources:
                return "unknown", f"`{name}` (a parameter of {scope.name}, called from elsewhere)"
            kind = _worst(k for k, _ in sources)
            detail = next(d for k, d in sources if k == kind)
            return kind, f"`{name}`, a parameter of {scope.name}, which is called with {detail}"
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets
            ):
                kind, detail = _classify(tree, node.value, scope, depth + 1)
                return kind, f"`{name}` comes from {detail}"
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            kind, detail = _classify(tree, node.value, None, depth + 1)
            return kind, f"`{name}` comes from {detail}"
    return "unknown", f"`{name}` (origin not found in this file)"


RANK = {"outside": 3, "unknown": 2, "program": 1, "fixed": 0}


def _worst(kinds) -> str:
    return max(kinds, key=RANK.__getitem__, default="fixed")


def _call_evidence(tree: ast.AST, call: ast.Call) -> Evidence:
    scope = _enclosing_function(tree, call)
    values = [op for arg in call.args for op in _operands(arg)]
    results = [_classify(tree, v, scope, 0) for v in values]
    kind = _worst(k for k, _ in results)
    if kind == "fixed":
        return Evidence("The command is a fixed value with no variables.", True)
    details = "; ".join(d for k, d in results if k != "fixed")
    if kind == "program":
        return Evidence(f"Only values generated by the program reach this call: {details}.", True)
    if kind == "outside":
        return Evidence(f"Outside input reaches this call: {details}.", False)
    return Evidence(f"Values of unknown origin reach this call: {details}.", False)


def _secret_evidence(line: str) -> Evidence:
    match = STRING_LITERAL.search(line)
    if not match:
        return Evidence(None, False)
    value = match.group(2)
    if PLACEHOLDER.search(value):
        return Evidence(f"The value {value!r} looks like a placeholder, not a real credential.", True)
    return Evidence("The value has the shape of a real credential, not a placeholder.", False)
