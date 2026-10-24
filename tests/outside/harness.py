"""Outside-the-process harness: build the wheel, install it into a FRESH venv,
run a host program (a "driver") there, read what it printed.

THIS MODULE IMPORTS NO ``xaidr``, and that is the point of it. A test that
imports the module under test checks the source tree in its own process; this
checks the ARTIFACT a user installs, in a process of its own, the way paid's
vendoring and every pip user receive it (global CLAUDE.md: "Milestone checks
reach the system from OUTSIDE the process").

Three ways a run here could silently check the wrong thing, each refused:

* the source tree shadows the wheel — drivers run with ``python -I`` (no cwd,
  no PYTHONPATH, no user site) from a temporary cwd, and every driver refuses
  unless ``xaidr.__file__`` is inside the venv's own site-packages
  (memory: xaidr-report-scripts-shadow-the-wheel);
* a stale wheel — the wheel is built from the given tree on every call;
* a shared environment — each venv is created empty with ``venv`` and gets the
  wheel with ``--no-deps --no-index`` unless a caller names extra packages.
"""
from __future__ import annotations

import json
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DRIVERS = Path(__file__).resolve().parent / "drivers"


def build_wheel(tree: Path, out: Path) -> Path:
    """Build a wheel from ``tree`` with hatchling, in a subprocess."""
    out.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        [sys.executable, "-c",
         f"from hatchling.build import build_wheel; print(build_wheel({str(out)!r}))"],
        cwd=tree, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"wheel build failed in {tree}:\n{r.stderr}")
    return out / r.stdout.strip().splitlines()[-1]


def fresh_venv(where: Path, wheel: Path, *extra: str) -> Path:
    """A new venv at ``where`` holding ``wheel`` (and ``extra`` from PyPI, if
    given). Returns its interpreter."""
    venv.EnvBuilder(with_pip=True, clear=True).create(where)
    py = where / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    cmd = [str(py), "-m", "pip", "install", "--quiet", "--disable-pip-version-check"]
    r = subprocess.run(cmd + ["--no-deps", "--no-index", str(wheel)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"wheel install failed:\n{r.stderr}")
    if extra:
        r = subprocess.run(cmd + list(extra), capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"installing {extra} failed:\n{r.stderr}")
    return py


def run_driver(py: Path, driver: str, cwd: Path, *args: str) -> dict:
    """Run ``drivers/<driver>`` with ``-I`` from ``cwd``; parse its one JSON line."""
    r = subprocess.run([str(py), "-I", str(DRIVERS / driver), *args],
                       cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"driver {driver} exited {r.returncode}:\n{r.stdout}\n{r.stderr}")
    return json.loads(r.stdout.strip().splitlines()[-1])


if __name__ == "__main__":
    # Evidence runs: harness.py <tree> <workdir> <driver> [pip extras ...] [-- driver args ...]
    argv = sys.argv[1:]
    driver_args = argv[argv.index("--") + 1:] if "--" in argv else []
    argv = argv[:argv.index("--")] if "--" in argv else argv
    tree, work, driver = Path(argv[0]), Path(argv[1]), argv[2]
    wheel = build_wheel(tree, work / "dist")
    py = fresh_venv(work / "venv", wheel, *argv[3:])
    print(json.dumps(run_driver(py, driver, work, *driver_args), indent=1, sort_keys=True))
