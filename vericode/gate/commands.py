"""`vericode install` and `vericode doctor`: turn the hook on in any repo, and
check that everything the hook needs is in place. See CLAUDE.md in this folder.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import yaml
from rich.console import Console
from rich.markup import escape

from vericode.gate.ui import use_ascii

VERICODE_HOME = Path(__file__).resolve().parents[2]
HOOK_ID = "vericode"
# The user-space install from ollama.com's Linux tarball, which isn't on PATH by default.
OLLAMA_FALLBACK = Path.home() / ".local" / "ollama" / "bin" / "ollama"


def _console() -> Console:
    return Console(highlight=False)


def hook_entry() -> str:
    return f"uv run --project {shlex.quote(str(VERICODE_HOME))} python -m vericode.gate.cli"


def hook_config() -> dict:
    return {
        "repo": "local",
        "hooks": [{
            "id": HOOK_ID,
            "name": "Vericode (offline AI code verification)",
            "entry": hook_entry(),
            "language": "system",
            "pass_filenames": False,
            "always_run": True,
            "verbose": True,
        }],
    }


def _git_root(path: Path) -> Path | None:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        capture_output=True, text=True,
    )
    return Path(result.stdout.strip()) if result.returncode == 0 else None


def _has_vericode(config: dict) -> bool:
    return any(
        hook.get("id") == HOOK_ID
        for repo in config.get("repos") or []
        for hook in repo.get("hooks") or []
    )


def write_config(root: Path) -> str:
    """Adds the Vericode hook to root/.pre-commit-config.yaml, keeping any
    hooks already there. Returns "created", "added" or "present"."""
    path = root / ".pre-commit-config.yaml"
    if not path.exists():
        path.write_text(yaml.safe_dump({"repos": [hook_config()]}, sort_keys=False))
        return "created"
    config = yaml.safe_load(path.read_text()) or {}
    if _has_vericode(config):
        return "present"
    config.setdefault("repos", []).append(hook_config())
    path.write_text(yaml.safe_dump(config, sort_keys=False))
    return "added"


def install(target: str) -> int:
    console = _console()
    root = _git_root(Path(target).expanduser())
    if root is None:
        console.print(f"[bold red]{escape(target)} is not inside a git repository.[/bold red]")
        console.print(f"Run [bold]git init {escape(target)}[/bold] first, or pass a repo path.")
        return 2

    state = write_config(root)
    hooked = subprocess.run(
        [sys.executable, "-m", "pre_commit", "install"],
        cwd=root, capture_output=True, text=True,
    )
    if hooked.returncode != 0:
        console.print("[bold red]Couldn't install the git hook.[/bold red]")
        console.print(escape((hooked.stderr or hooked.stdout).strip()))
        return 1

    note = {
        "created": "created .pre-commit-config.yaml",
        "added": "added Vericode to your existing .pre-commit-config.yaml",
        "present": ".pre-commit-config.yaml already had Vericode",
    }[state]
    console.print(f"[bold green]Vericode is on for {escape(str(root))}[/bold green] ({note}).")
    console.print("Every [bold]git commit[/bold] there is now checked. Try it:")
    console.print(f"  cd {escape(shlex.quote(str(root)))} && git add . && git commit -m \"...\"")
    console.print("Check your setup any time with [bold]uv run vericode doctor[/bold]"
                  f" (from {escape(str(VERICODE_HOME))}).")
    return 0


def _ollama_binary() -> str | None:
    found = shutil.which("ollama")
    if found:
        return found
    return str(OLLAMA_FALLBACK) if OLLAMA_FALLBACK.exists() else None


def run_checks(cwd: Path) -> list[tuple[str, bool, str, bool]]:
    """(name, ok, detail or fix, required) for everything the hook needs."""
    checks: list[tuple[str, bool, str, bool]] = []
    add = lambda name, ok, detail, required=True: checks.append((name, ok, detail, required))

    add("git", bool(shutil.which("git")), "install git" if not shutil.which("git") else "found")
    add("uv", bool(shutil.which("uv")),
        "found" if shutil.which("uv") else "install uv: https://docs.astral.sh/uv/")

    binary = _ollama_binary()
    if binary is None:
        add("Ollama installed", False, "install Ollama: https://ollama.com/download")
    elif not shutil.which("ollama"):
        add("Ollama installed", True,
            f"found at {binary}, not on PATH. Fish: fish_add_path {Path(binary).parent} · "
            f"bash/zsh: export PATH=\"{Path(binary).parent}:$PATH\"")
    else:
        add("Ollama installed", True, binary)

    from vericode.llm_explain import explainer
    try:
        explainer._client().list()
        add("Ollama running", True, "reachable")
        try:
            explainer.pick_model.cache_clear()
            add("AI model", True, explainer.pick_model())
        except RuntimeError:
            add("AI model", False, f"run: ollama pull {explainer.PRIMARY_MODEL}")
    except Exception:
        add("Ollama running", False, "start it in another terminal: ollama serve")
        add("AI model", False, "start Ollama first, then check again")

    from vericode.import_check.checker import DATA_DIR as PYPI_DIR
    lists = all((PYPI_DIR / name).exists() for name in ("pypi_all.txt", "pypi_top.txt"))
    add("PyPI name lists", lists, "found" if lists else "run ./setup.sh while online")

    try:
        import pybetterleaks  # noqa: F401
        add("Betterleaks", True, "installed")
    except ImportError:
        add("Betterleaks", False, "run: uv sync")

    from vericode.security_scan.scanner import DATA_DIR as RULES_DIR
    rules = (RULES_DIR / "rules.yml").exists()
    add("Semgrep rules (optional)", rules,
        "cached" if rules else "only for VERICODE_SEMGREP=1; run ./setup.sh while online",
        required=False)

    root = _git_root(cwd)
    if root is not None:
        config_path = root / ".pre-commit-config.yaml"
        configured = config_path.exists() and _has_vericode(yaml.safe_load(config_path.read_text()) or {})
        hooked = (root / ".git" / "hooks" / "pre-commit").exists()
        add(f"Hook in {root.name}", configured and hooked,
            "on" if configured and hooked
            else f"run: uv run vericode install {shlex.quote(str(root))}",
            required=False)
    return checks


def doctor(cwd: str = ".") -> int:
    console = _console()
    ok_mark, bad_mark, warn_mark = ("OK", "X ", "! ") if use_ascii(False) else ("✅", "❌", "⚠️ ")
    checks = run_checks(Path(cwd))
    console.print("[bold]Vericode doctor[/bold]")
    for name, ok, detail, required in checks:
        mark = ok_mark if ok else (bad_mark if required else warn_mark)
        console.print(f" {mark} [bold]{escape(name)}[/bold]: {escape(detail)}")

    failed = [name for name, ok, _, required in checks if required and not ok]
    if failed:
        console.print(f"[bold red]{len(failed)} problem(s) to fix[/bold red]: {escape(', '.join(failed))}.")
        return 1
    console.print("[bold green]All set.[/bold green] Commits are checked fully offline.")
    return 0
