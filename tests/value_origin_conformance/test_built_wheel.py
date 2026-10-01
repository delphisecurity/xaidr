"""V-5: the PSL ships in a BUILT wheel and works from outside the source tree.

P1 and L1 run in-tree and cannot see a packaging omission: a data file left out
of the wheel faults every ``authority_of`` in production while every in-tree
test stays green. So: build the wheel, install it into a temporary target, and
from an isolated interpreter (``-I``: no cwd, no PYTHONPATH, no user site) run
``authority_of("https://a.b.github.io/")`` and require ``dns:b.github.io`` — a
PRIVATE-section rule, which only the vendored list can answer.
"""
from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_the_built_wheel_answers_from_its_own_psl(tmp_path):
    try:
        from hatchling.builders.wheel import WheelBuilder  # noqa: F401
    except ImportError:
        pytest.skip("hatchling is not importable, so no wheel can be built here. CI's "
                    "`full` config installs it via the dev extra and runs this check.")
    built = subprocess.run(
        [sys.executable, "-c",
         "import sys; from hatchling.build import build_wheel; "
         f"print(build_wheel({str(tmp_path)!r}))"],
        cwd=ROOT, capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    wheel = tmp_path / built.stdout.strip().splitlines()[-1]
    names = zipfile.ZipFile(wheel).namelist()
    for mod in ("_psl_data.py", "_idna_data.py", "__init__.py", "_ledger.py"):
        assert f"xaidr/value_origin/{mod}" in names, f"{mod} missing from the wheel"

    target = tmp_path / "site"
    inst = subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps",
                           "--no-index", "--quiet", "--target", str(target), str(wheel)],
                          capture_output=True, text=True)
    assert inst.returncode == 0, inst.stderr
    probe = (
        "import sys; sys.path.insert(0, %r)\n"
        "import xaidr.value_origin as v\n"
        "assert v.__file__.startswith(%r), v.__file__\n"
        "print(v.authority_of('https://a.b.github.io/').key())\n" % (str(target), str(target)))
    run = subprocess.run([sys.executable, "-I", "-c", probe], cwd=tmp_path,
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "dns:b.github.io"
