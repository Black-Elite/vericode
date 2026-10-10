import subprocess

import yaml

from vericode.gate import commands
from vericode.gate.cli import main


def git_repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


def hook_ids(path):
    config = yaml.safe_load((path / ".pre-commit-config.yaml").read_text())
    return [hook["id"] for repo in config["repos"] for hook in repo["hooks"]]


def test_install_creates_config_and_git_hook(tmp_path):
    repo = git_repo(tmp_path)
    assert main(["install", str(repo)]) == 0
    assert hook_ids(repo) == ["vericode"]
    assert (repo / ".git" / "hooks" / "pre-commit").exists()


def test_install_keeps_existing_hooks_and_is_idempotent(tmp_path):
    repo = git_repo(tmp_path)
    (repo / ".pre-commit-config.yaml").write_text(
        "repos:\n- repo: local\n  hooks:\n  - id: black\n    name: black\n    entry: black\n    language: system\n"
    )
    assert commands.write_config(repo) == "added"
    assert commands.write_config(repo) == "present"
    assert hook_ids(repo) == ["black", "vericode"]


def test_install_outside_a_repo_fails_with_a_hint(tmp_path, capsys):
    assert main(["install", str(tmp_path)]) == 2
    assert "git init" in capsys.readouterr().out


def test_hook_entry_points_at_this_checkout():
    assert str(commands.VERICODE_HOME) in commands.hook_entry()
    assert commands.hook_entry().endswith("python -m vericode.gate.cli")


def test_doctor_reports_ollama_down_with_the_fix(tmp_path, monkeypatch, capsys):
    def down():
        raise ConnectionError("refused")
    monkeypatch.setattr("vericode.llm_explain.explainer._client", down)
    assert main(["doctor"]) == 1
    assert "ollama serve" in capsys.readouterr().out
