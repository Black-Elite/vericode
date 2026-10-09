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

echo "== Pulling local LLM (Ollama, Qwen2.5-Coder 7B) =="
if ! command -v ollama &> /dev/null; then
  echo "Ollama not found. Install it from https://ollama.com before continuing."
  exit 1
fi
ollama pull qwen2.5-coder:7b
# Fallback for slower hardware — uncomment if needed:
# ollama pull qwen2.5-coder:3b

echo "== Caching Semgrep offline rulesets =="
# --dryrun caches nothing, so fetch the rules as files
mkdir -p vericode/security_scan/data
curl -fsSL -o vericode/security_scan/data/secrets.yml https://semgrep.dev/c/p/secrets
curl -fsSL -o vericode/security_scan/data/security-audit.yml https://semgrep.dev/c/p/security-audit
curl -fsSL -o vericode/security_scan/data/system-call.yml https://semgrep.dev/c/r/python.lang.security.audit.dangerous-system-call

echo "== Building offline PyPI package name snapshot =="
uv run python scripts/build_pypi_snapshot.py

echo "== Setup done. You can now disconnect from the internet. =="
