#!/usr/bin/env bash
# Phase 0 — run this once, while you still have internet.
# Everything downloaded here is what lets the tool run fully offline later.
set -euo pipefail

echo "== Installing Python dependencies =="
pip install -r requirements.txt

echo "== Pulling local LLM (Ollama, Qwen2.5-Coder 7B) =="
if ! command -v ollama &> /dev/null; then
  echo "Ollama not found. Install it from https://ollama.com before continuing."
  exit 1
fi
ollama pull qwen2.5-coder:7b
# Fallback for slower hardware — uncomment if needed:
# ollama pull qwen2.5-coder:3b

echo "== Caching Semgrep offline rulesets =="
semgrep --config p/secrets --config p/python --dryrun --metrics=off .

echo "== Building offline PyPI package name snapshot =="
python3 scripts/build_pypi_snapshot.py

echo "== Setup done. You can now disconnect from the internet. =="
