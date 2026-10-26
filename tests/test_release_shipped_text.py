"""The release step 3a gate reads the docstrings and comments of every shipped
.py file, as well as every data file (docs/releasing.md, step 3a).

The phrases here are synthetic: the real list is maintainer-local and is never
in the repository."""
from __future__ import annotations

import pathlib
import subprocess
import sys
import zipfile

REPO = pathlib.Path(__file__).resolve().parent.parent
GATE = REPO / "scripts" / "release_shipped_text.py"
PHRASE = "zebra-quartz-phrase"


def _wheel(tmp_path, files):
    whl = tmp_path / "pkg-0.0.0-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    return whl


def _gate(whl, tmp_path):
    phrases = tmp_path / "phrases.txt"
    phrases.write_text(f"\n{PHRASE}\n\n", encoding="utf-8")
    return subprocess.run([sys.executable, str(GATE), str(whl), "--phrases", str(phrases)],
                          capture_output=True, text=True)


def test_a_phrase_in_a_docstring_or_a_comment_of_a_shipped_py_file_is_red(tmp_path):
    whl = _wheel(tmp_path, {
        "pkg/__init__.py": f'"""Module docstring naming {PHRASE}."""\nX = 1\n',
        "pkg/mod.py": f"def f():\n    # a comment naming {PHRASE}\n    return 1\n",
        "pkg/data.json": "{}",
    })
    r = _gate(whl, tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "pkg/__init__.py:1" in r.stdout and "pkg/mod.py:2" in r.stdout, r.stdout
    assert PHRASE not in r.stdout, "the gate printed the phrase it exists to keep out"


def test_a_phrase_in_code_that_is_not_prose_is_not_read(tmp_path):
    """Only docstrings and comments are prose; an identifier or a string the code
    uses is code."""
    whl = _wheel(tmp_path, {"pkg/mod.py": f'NAME = "{PHRASE}"\n', "pkg/data.json": "{}"})
    r = _gate(whl, tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_phrase_or_a_notice_shape_in_a_data_file_is_red(tmp_path):
    notice_id = "C" + "VE-2026-0001"
    whl = _wheel(tmp_path, {"pkg/a.json": f'{{"d": "{PHRASE}"}}',
                            "pkg/b.txt": f"fixed in {notice_id}"})
    r = _gate(whl, tmp_path)
    assert r.returncode == 1 and "pkg/a.json:1" in r.stdout and "pkg/b.txt:1" in r.stdout, r.stdout


def test_a_clean_wheel_is_green_and_says_what_it_read(tmp_path):
    whl = _wheel(tmp_path, {"pkg/mod.py": '"""Fine."""\n', "pkg/data.json": "{}"})
    r = _gate(whl, tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 data file(s)" in r.stdout and "1 .py file(s)" in r.stdout, r.stdout


def test_an_empty_phrase_list_cannot_run(tmp_path):
    whl = _wheel(tmp_path, {"pkg/mod.py": '"""Fine."""\n'})
    empty = tmp_path / "empty.txt"
    empty.write_text("\n\n", encoding="utf-8")
    r = subprocess.run([sys.executable, str(GATE), str(whl), "--phrases", str(empty)],
                       capture_output=True, text=True)
    assert r.returncode == 2, r.stdout + r.stderr
