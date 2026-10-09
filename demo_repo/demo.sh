#!/usr/bin/env bash
# Builds a throwaway "notes app" git repo for demoing Vericode.
#   ./demo_repo/demo.sh reset   fresh repo with the hook installed; stages act 1 (should be blocked)
#   ./demo_repo/demo.sh fix     stages the fixed export.py and notify.py (should pass)
#   ./demo_repo/demo.sh act2    stages backup.py and tools.py (AI tells the real risk from the false alarm)
#   ./demo_repo/demo.sh warm    loads the local AI again (run right before going on stage)
# Repo location: $DEMO_DIR, default ~/vericode-demo.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERICODE="$(dirname "$HERE")"
DEMO_DIR="${DEMO_DIR:-$HOME/vericode-demo}"
MARKER="$DEMO_DIR/.git/vericode-demo"

copy_templates() {
  for tmpl in "$HERE/$1"/*.tmpl; do
    cp "$tmpl" "$DEMO_DIR/$(basename "${tmpl%.tmpl}")"
  done
}

# Generated at reset time so no secret-looking string is ever committed to vericode.
fake_slack_token() {
  python3 -c '
import secrets, string
alnum = string.ascii_letters + string.digits
print(f"xoxb-{secrets.randbelow(10**11):011d}-{secrets.randbelow(10**12):012d}-"
      + "".join(secrets.choice(alnum) for _ in range(24)))'
}

# Loads the model and caches the fixed prompt text in Ollama, so the first
# commit on stage isn't the slow one. Never fails the script.
warm() {
  echo "Warming up the local AI..."
  local start model
  start=$(date +%s)
  if model=$(uv run --project "$VERICODE" python -c '
from vericode.llm_explain.explainer import warm_up
model = warm_up()
print(model or "")
raise SystemExit(0 if model else 1)'); then
    echo "Local AI ready: $model ($(( $(date +%s) - start ))s)."
  else
    echo "Local AI not reachable. Is Ollama running? Commits will show the static checks only." >&2
  fi
}

require_demo_repo() {
  if [ ! -e "$MARKER" ]; then
    echo "No demo repo at $DEMO_DIR. Run: $0 reset" >&2
    exit 1
  fi
  cd "$DEMO_DIR"
}

reset() {
  if [ -e "$DEMO_DIR" ] && [ ! -e "$MARKER" ]; then
    echo "Refusing to delete $DEMO_DIR: it wasn't created by this script." >&2
    exit 1
  fi
  rm -rf "$DEMO_DIR"
  mkdir -p "$DEMO_DIR"
  cd "$DEMO_DIR"
  git init -q
  touch "$MARKER"
  git config user.name "Vericode Demo"
  git config user.email "demo@vericode.local"

  copy_templates base
  cat > .pre-commit-config.yaml <<EOF
repos:
  - repo: local
    hooks:
      - id: vericode
        name: Vericode (offline AI code verification)
        entry: uv run --project "$VERICODE" python -m vericode.gate.cli
        language: system
        pass_filenames: false
        always_run: true
        verbose: true
EOF
  git add -A
  git commit -q -m "Notes app: SQLite storage"
  uv run --project "$VERICODE" pre-commit install >/dev/null

  copy_templates act1
  sed -i "s/__SLACK_TOKEN__/$(fake_slack_token)/" notify.py
  git add export.py notify.py
  warm
  echo "Demo repo ready at $DEMO_DIR with export.py and notify.py staged."
  echo "Next: cd $DEMO_DIR && git commit -m \"Add PDF export and Slack reminders\"   (should be blocked)"
}

fix() {
  require_demo_repo
  copy_templates fix
  git add export.py notify.py
  echo "Staged the fixed export.py and notify.py."
  echo "Next: git commit -m \"Add PDF export and Slack reminders\"   (should pass)"
}

act2() {
  require_demo_repo
  copy_templates act2
  git add backup.py tools.py
  echo "Staged backup.py and tools.py."
  echo "Next: git commit -m \"Add backup and server check\"   (AI should flag tools.py, dismiss backup.py)"
}

case "${1:-}" in
  reset) reset ;;
  fix) fix ;;
  act2) act2 ;;
  warm) warm ;;
  *) echo "Usage: $0 reset|fix|act2|warm" >&2; exit 1 ;;
esac
