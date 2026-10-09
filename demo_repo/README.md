# Demo repo

`demo.sh` builds a throwaway "notes app" git repo (default `~/vericode-demo`, override with `DEMO_DIR`) with the Vericode hook installed, then stages changes that show each feature. Run `reset` before every rehearsal so each run starts from the same state.

The source files are stored as `.tmpl` so Vericode's own hook and GitHub never see a fake secret or a fake import. The Slack token is generated fresh on each `reset` and is not a real credential.

## Demo script

| Step | Command | What happens |
|---|---|---|
| 1 | `./demo_repo/demo.sh reset`, then in `~/vericode-demo`: `git commit -m "Add PDF export and Slack reminders"` | **Blocked.** Fake import `markdown_pdf_export` (high), obscure package `slack_notify` (medium, possible slopsquat), hardcoded Slack token (high), each explained by the local AI |
| 2 | `./demo_repo/demo.sh fix`, then commit again | **Passes.** Real package, token read from the environment |
| 3 | `./demo_repo/demo.sh act2`, then `git commit -m "Add backup and server check"` | Two findings with the **same rule and severity**. The AI should mark `tools.py` (user input reaches `os.system`) as real and `backup.py` (only today's date) as a false alarm |
| 4 | Turn wifi off and repeat step 1 | Still works |

To show the override instead of the fix in step 2: `VERICODE_OVERRIDE=1 git commit -m "..."` (once Layer 4 supports it).

## Notes

- Run on the presentation laptop with 7B. On a CPU-only laptop with 3B, AI calls take 30–50s each and need `VERICODE_TIMEOUT=90`.
- Each step stages at most 3 findings that go to the AI, matching the default `VERICODE_MAX_AI_FINDINGS=3`.
- `reset` only deletes `DEMO_DIR` if this script created it.
