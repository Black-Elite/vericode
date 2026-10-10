# Vericode

> "AI writes code that looks right. Vericode catches what isn't, and a local AI tells you which warnings are real."

A Git pre-commit hook that flags hallucinated packages, slopsquatting risks,
hardcoded secrets, dangerous calls, and new code that skips a safety check the
rest of your codebase always runs, in the lines you're committing, then has
a local AI judge each one, explain it and write the fix. It runs on an ordinary
laptop with no GPU, and nothing is uploaded: your code and secrets never leave
the machine.

Built for **AppBuildersPH Hackathon 2026** (theme: Local AI).

<details>
<summary><b>Watch it run</b> — a commit blocked, judged by the local AI, fixed, and allowed through, on a laptop with no GPU.</summary>

![Vericode blocking a commit](assets/demo.gif)

</details>

## Why local AI

Vericode reads your private code on every commit: the changed files, the code
around each problem, and any secrets it finds. Doing that with a cloud AI means
uploading that code and those secrets to someone else's server, which is
exactly what companies like Samsung banned after source code leaked through a
cloud AI tool. Running a small model (Qwen2.5-Coder 1.5B, which judges each
finding and writes the fix) on the developer's own laptop, even one with no
GPU, keeps code private, works on flights and locked-down networks, has no
per-scan cost, and stays fast enough to run on every commit. A tool meant to
make AI code trustworthy shouldn't leak the code it's protecting.

## How it works

```
staged files (only the lines this commit adds are reported)
   │
   ├─► vericode/import_check   no AI: packages that don't exist on PyPI (high),
   │                            obscure ones that may be slopsquats (medium)
   ├─► vericode/security_scan  no AI: Betterleaks for secrets; a built-in check for
   │                            eval / exec / os.system / shell=True; Semgrep (optional)
   ├─► vericode/consistency    no AI: compares new code with the rest of the repo:
   │                            a handler that skips the check its siblings all run
   │                            ("4 of 4 @route handlers call check_owner()"), or copied logic
   ▼
vericode/llm_explain  local AI (Qwen2.5-Coder 1.5B via Ollama):
   │                  1. code analysis states what reaches the flagged line
   │                     ("host comes from sys.argv", "only date.today()")
   │                  2. the model judges real risk vs. false alarm, explains, writes the fix
   │                  3. a false alarm only counts when that evidence agrees
   ▼
vericode/gate  report, then blocks or allows the commit
```

- Secret values are blanked before the model sees the code and again in its answer.
- Fake-import findings skip the model: it can't clear them, and Layer 1's "Did you mean" is a better fix.
- At most 3 findings per commit go to the model, most severe first.

Each layer has a `CLAUDE.md` in its folder with its spec and "done when" checklist.

## Prerequisites

Install these yourself first. `./setup.sh` checks for them but can't install them for you:

- **[uv](https://docs.astral.sh/uv/)**: manages Python (3.11+, installed by uv if missing) and all dependencies.
- **[Ollama](https://ollama.com)**, running, before you run `setup.sh`:
  - Windows / Mac: installer from ollama.com.
  - Arch: `sudo pacman -S ollama`.
  - Anything else: see ollama.com/download.
- **git**: to clone this repo and for `pre-commit` to hook into.

Everything else (Rich, Semgrep, Betterleaks, pytest, pre-commit, the `ollama`
Python client, the Qwen2.5-Coder 1.5B model) is installed by `./setup.sh`.

## Setup

```bash
git clone https://github.com/Black-Elite/vericode.git
cd vericode
./setup.sh                 # one-time: uv sync, pulls the model, caches Semgrep rules, builds the PyPI name lists
uv run vericode doctor     # checks everything is ready, and prints the fix for anything that isn't
```

Needs internet only for this one-time step. Everything runs offline after.

## Use it on your own project

From the `vericode` folder, point it at any git repo:

```bash
uv run vericode install ~/path/to/your-project
```

That adds Vericode to the project's `.pre-commit-config.yaml` (any hooks
already there are kept) and turns on the git hook. Every `git commit` in that
project is now checked. Running it again is safe.

Keep Ollama running (`ollama serve`) while you work. Without it, commits still
get the static checks, but no AI verdicts.

| Command | What it does |
|---|---|
| `uv run vericode install <path>` | Turns the hook on in a repo |
| `uv run vericode doctor` | Checks git, uv, Ollama, the model and the offline lists; prints the fix for each problem |
| `./demo_repo/demo.sh reset` | Builds a demo repo to try it on (see Demo below) |

## Usage

Commit normally:

```bash
git add .
git commit -m "..."
```

Vericode runs automatically. A blocked commit can be forced through with
`VERICODE_OVERRIDE=1 git commit ...` after reviewing the report; the override is
shown in the output.

| Setting | Default | Use |
|---|---|---|
| `VERICODE_MODEL` | first installed of `qwen2.5-coder:1.5b`, `:3b`, `:7b` | Pick the model |
| `VERICODE_TIMEOUT` | `30` seconds | Time limit per AI call |
| `VERICODE_MAX_AI_FINDINGS` | `3` | Findings sent to the AI per commit |
| `VERICODE_SEMGREP` | off | `1` adds Semgrep's broader rules (about 3s slower) |
| `VERICODE_KEEP_ALIVE` | `30m` | How long Ollama keeps the model loaded |
| `VERICODE_OVERRIDE` | off | `1` commits anyway |

## Demo

`demo_repo/demo.sh` builds a throwaway repo with the hook installed:
`reset` (a commit that gets blocked), `fix` (one that passes), `act2` (two
identical warnings where the AI clears one and confirms the other), `act3` (a
new handler that skips the ownership check its four siblings run) and `warm`
(loads the model right before presenting). See [`demo_repo/README.md`](demo_repo/README.md).

Measured on a laptop with no GPU: about 1 second for the static checks, about
8 seconds per AI-reviewed finding; demo act 1 in about 9s, act 2 in about 16s,
act 3 in about 4–9s.

## What runs locally vs. what needs internet

**At commit time, everything runs locally:** import checking, secret and call
scanning, the evidence helper and the AI model. No network calls are made;
Betterleaks' live key validation is turned off.

**Internet is used once, by `./setup.sh`,** to download the model, Semgrep's
rules and the PyPI name lists.

## Known limitations

- Python only (except secret scanning, which covers any file).
- By default, only the most dangerous calls are checked; SQL injection and similar need `VERICODE_SEMGREP=1`.
- The 1.5B model sometimes calls a placeholder secret (e.g. `"changeme"`) a real risk. This blocks the commit, which is the safe direction.
- The AI's fix is a suggestion: in testing, one "fix" for `eval(input())` returned the same unsafe line.
- The consistency check needs at least 3 sibling handlers sharing a decorator, and only compares guard-like calls (`check_owner`, `require_login`, ...). Duplicates are found only when the structure matches; rewritten copies are missed.

## Disclosures

**Models**
- [Qwen2.5-Coder 1.5B](https://ollama.com/library/qwen2.5-coder) (default), run locally via Ollama. 3B or 7B can be used via `VERICODE_MODEL`.

**Technologies and frameworks**
- Python 3.11+, managed with [uv](https://docs.astral.sh/uv/)
- [Ollama](https://ollama.com) and its Python client
- [Betterleaks](https://github.com/siemens/betterleaks) via `pybetterleaks` (secret scanning)
- [Semgrep](https://semgrep.dev) community rules (optional)
- [Rich](https://github.com/Textualize/rich) (report), [pre-commit](https://pre-commit.com) (hook), PyYAML, certifi, pytest
- Python standard library: `ast`, `importlib`, `sys.stdlib_module_names`

**APIs and cloud services**
- None at commit time.
- During one-time setup only: the Ollama model library, pypi.org, the top-pypi-packages list on GitHub Pages, and the Semgrep rule registry.

**Existing code and assets**
- PyPI's public package index and [top-pypi-packages](https://hugovk.github.io/top-pypi-packages/) (package name lists)
- Semgrep community rules (downloaded by `scripts/build_semgrep_rules.py`)
- All other code in this repository was written during the hackathon.

**AI development tools**
- [Claude Code](https://claude.com/claude-code) was used to help write code, tests and documentation.

## Development

```bash
uv sync --dev
uv run pytest tests/                 # unit tests, no model needed
uv run pytest -m live -s -v          # against the real local model (needs Ollama running)
```
