#!/usr/bin/env bash
# Phase 0 — run this once, while you still have internet.
# Everything downloaded here is what lets the tool run fully offline later.
set -euo pipefail

echo "== Installing Python dependencies (uv) =="
if ! command -v uv &> /dev/null; then
  echo "uv not found. Install it from https://docs.astral.sh/uv/ before continuing."
  exit 1
fi
uv sync --dev

echo "== Pulling local LLM (Ollama, Qwen2.5-Coder 1.5B, runs on CPU) =="
OLLAMA=ollama
if ! command -v ollama &> /dev/null; then
  # ollama.com's Linux tarball, unpacked into the home folder, isn't on PATH
  if [ -x "$HOME/.local/ollama/bin/ollama" ]; then
    OLLAMA="$HOME/.local/ollama/bin/ollama"
    echo "Using $OLLAMA (not on PATH; add $HOME/.local/ollama/bin to PATH to run 'ollama' yourself)."
  else
    echo "Ollama not found. Install it from https://ollama.com/download, then run ./setup.sh again."
    exit 1
  fi
fi
if ! "$OLLAMA" list &> /dev/null; then
  echo "Ollama is installed but not running. Start it in another terminal with: ollama serve"
  echo "Then run ./setup.sh again."
  exit 1
fi
"$OLLAMA" pull qwen2.5-coder:1.5b
# Optional, for machines with a GPU: ollama pull qwen2.5-coder:7b

echo "== Caching Semgrep offline rulesets =="
# --dryrun caches nothing, so fetch the rules as files
uv run python scripts/build_semgrep_rules.py

echo "== Building offline PyPI package name snapshot =="
uv run python scripts/build_pypi_snapshot.py

echo "== Setup done. You can now disconnect from the internet. =="
echo
uv run vericode doctor || true
echo
echo "Next: turn Vericode on in your project:"
echo "  uv run vericode install /path/to/your/project"
echo "Or try the demo: ./demo_repo/demo.sh reset"
