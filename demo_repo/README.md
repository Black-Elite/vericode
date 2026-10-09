# Demo repo

`demo.sh` builds a throwaway "notes app" git repo (default `~/vericode-demo`, override with `DEMO_DIR`) with the Vericode hook installed, then stages changes that show each feature. Run `reset` before every rehearsal so each run starts from the same state.

The source files are stored as `.tmpl` so Vericode's own hook and GitHub never see a fake secret or a fake import. The Slack token is generated fresh on each `reset` and is not a real credential.

## Demo script

| Step | Command | What happens |
|---|---|---|
| 1 | `./demo_repo/demo.sh reset`, then in `~/vericode-demo`: `git commit -m "Add PDF export and Slack reminders"` | **Blocked.** Fake import `markdown_pdf_export` (high, "Did you mean 'markdown-pdf'?") and obscure package `slack_notify` (medium, possible slopsquat), both from Layer 1 without the AI; hardcoded Slack token (high), where the local AI says "real risk" and writes `SLACK_TOKEN = os.environ['SLACK_TOKEN']` |
| 2 | `./demo_repo/demo.sh fix`, then commit again | **Passes.** Real package, token read from the environment |
| 3 | `./demo_repo/demo.sh act2`, then `git commit -m "Add backup and server check"` | Two findings with the **same rule and severity**. The local AI marks `backup.py` as a false alarm (only today's date reaches `os.system`; "Fix: none needed") and `tools.py` as a real risk (command-line input), with fix `subprocess.run(['ping', '-c', '1', host], check=True)`. Only `tools.py` blocks |
| 4 | Turn wifi off and repeat step 1 | Still works |

To show the override instead of the fix in step 2: `VERICODE_OVERRIDE=1 git commit -m "..."`.

**Right before going on stage:** run `./demo_repo/demo.sh warm`. `reset` already warms the local AI, but Ollama unloads the model after 30 idle minutes (`VERICODE_KEEP_ALIVE`). On a CPU-only laptop, a cold first commit took 23.7s; after warming, 9.8s.

## Notes

- Works on a laptop with no GPU: the default model, Qwen2.5-Coder 1.5B, takes about 8s per finding. Measured on CPU: act 1 about 9s, act 2 about 16s.
- Each step stages at most 3 findings that go to the AI, matching the default `VERICODE_MAX_AI_FINDINGS=3`.
- `reset` only deletes `DEMO_DIR` if this script created it.
