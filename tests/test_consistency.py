import subprocess
import textwrap

from vericode.consistency.checker import run

ROUTER = "def route(method, path):\n    return lambda fn: fn\n"

HANDLER = '''
@route("{method}", "/notes/<note_id>")
def {name}(note_id, user):
    note = db.get(note_id)
{guard}    db.{action}(note)
    return note
'''


def handler(name, method="GET", action="save", guarded=True, guard="check_owner(note, user)"):
    return HANDLER.format(
        name=name, method=method, action=action,
        guard=f"    {guard}\n" if guarded else "",
    )


def repo(tmp_path, committed: dict[str, str], staged: dict[str, str]):
    """A real git repo: `committed` files in history, `staged` ones added on top."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for name, src in committed.items():
        (tmp_path / name).write_text(textwrap.dedent(src))
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t",
                    "commit", "-q", "-m", "base"], check=True)
    for name, src in staged.items():
        (tmp_path / name).write_text(textwrap.dedent(src))
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    return [str(tmp_path / name) for name in staged]


SIBLINGS = "from router import route\n" + "".join(
    handler(n) for n in ("get_note", "update_note", "share_note", "archive_note")
)


def test_missing_owner_check_is_flagged_high(tmp_path):
    staged = repo(tmp_path, {"router.py": ROUTER, "api.py": SIBLINGS},
                  {"admin.py": "from router import route\n" + handler("delete_note", "DELETE", "delete", guarded=False)})
    [finding] = run(staged)
    assert finding.layer == "consistency"
    assert finding.severity == "high"
    assert "4 of 4 similar @route handlers call check_owner() before acting; delete_note doesn't" in finding.message
    assert "check_owner(note, user)" in finding.suggested_fix
    assert finding.line == 4  # the def line (the decorator is line 3); new, so the gate keeps it


def test_new_handler_in_the_same_file_is_compared_with_its_neighbours(tmp_path):
    staged = repo(tmp_path, {"router.py": ROUTER, "api.py": SIBLINGS},
                  {"api.py": SIBLINGS + handler("delete_note", "DELETE", "delete", guarded=False)})
    findings = [f for f in run(staged) if "delete_note" in f.message]
    assert len(findings) == 1


def test_guarded_handler_is_clean(tmp_path):
    staged = repo(tmp_path, {"router.py": ROUTER, "api.py": SIBLINGS},
                  {"admin.py": "from router import route\n" + handler("delete_note", "DELETE", "delete")})
    assert run(staged) == []


def test_fewer_than_three_siblings_is_not_a_pattern(tmp_path):
    two = "from router import route\n" + handler("get_note") + handler("update_note")
    staged = repo(tmp_path, {"router.py": ROUTER, "api.py": two},
                  {"admin.py": "from router import route\n" + handler("delete_note", guarded=False)})
    assert run(staged) == []


def test_inline_permission_raise_counts_as_a_guard(tmp_path):
    raise_guard = "if note.owner != user:\n        raise PermissionError('not yours')"
    siblings = "from router import route\n" + "".join(
        handler(n, guard=raise_guard) for n in ("a", "b", "c")
    )
    staged = repo(tmp_path, {"router.py": ROUTER, "api.py": siblings},
                  {"new.py": "from router import route\n" + handler("d", guarded=False)})
    [finding] = run(staged)
    assert "raise PermissionError" in finding.message


def test_shared_non_guard_calls_are_not_flagged(tmp_path):
    siblings = "from router import route\n" + "".join(
        handler(n, guard="log_event(note)") for n in ("a", "b", "c", "e")
    )
    staged = repo(tmp_path, {"router.py": ROUTER, "api.py": siblings},
                  {"new.py": "from router import route\n" + handler("d", guarded=False)})
    assert run(staged) == []


def test_undecorated_functions_are_not_pattern_checked(tmp_path):
    plain = "".join(f"def f{i}(x):\n    check_owner(x)\n    return x\n\n" for i in range(4))
    staged = repo(tmp_path, {"util.py": plain}, {"new.py": "def g(x):\n    return x\n"})
    assert run(staged) == []


DUE = '''
def {name}({arg}):
    if not {arg}.due:
        return "no due date"
    days = ({arg}.due - date.today()).days
    return f"due in {{days}} days" if days >= 0 else f"overdue by {{-days}} days"
'''


def test_copied_function_with_renamed_variables_is_a_duplicate(tmp_path):
    staged = repo(tmp_path, {"notes_api.py": "from datetime import date\n" + DUE.format(name="format_due", arg="note")},
                  {"reminders.py": "from datetime import date\n" + DUE.format(name="due_label", arg="n")})
    [finding] = run(staged)
    assert finding.severity == "low"
    assert "due_label has the same logic as format_due (notes_api.py:3)" in finding.message
    assert "Reuse format_due" in finding.suggested_fix


def test_short_functions_are_not_duplicates(tmp_path):
    staged = repo(tmp_path, {"a.py": "def a(x):\n    return x + 1\n"},
                  {"b.py": "def b(y):\n    return y + 1\n"})
    assert run(staged) == []


def test_unparseable_and_non_python_files_never_crash(tmp_path):
    staged = repo(tmp_path, {"ok.py": "x = 1\n"}, {"broken.py": "def broken(:\n", "notes.txt": "hello\n"})
    assert run(staged) == []


def test_works_outside_a_git_repo(tmp_path):
    (tmp_path / "router.py").write_text(ROUTER)
    (tmp_path / "api.py").write_text(SIBLINGS)
    new = tmp_path / "admin.py"
    new.write_text("from router import route\n" + handler("delete_note", guarded=False))
    [finding] = run([str(new)])
    assert finding.severity == "high"
