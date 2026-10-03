"""§4.5: the core imports the standard library and its own modules, nothing else.

Without this, open can add ``from ..sensor import X`` and paid's next vendor
breaks with an ImportError far from the cause. Parsed with ``ast`` so a lazy
import inside a function is caught too.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import xaidr.value_origin as vo

PKG = Path(vo.__file__).resolve().parent

# The stdlib modules the core may use. Named rather than derived from
# sys.stdlib_module_names, which does not exist on 3.10 (the floor).
STDLIB_ALLOWED = {
    "__future__", "bisect", "contextlib", "contextvars", "dataclasses", "enum",
    "fnmatch", "hashlib", "hmac", "ipaddress", "logging", "os", "posixpath", "re",
    "secrets", "threading", "types", "typing", "unicodedata", "urllib",
}


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield node.lineno, 0, a.name
        elif isinstance(node, ast.ImportFrom):
            yield node.lineno, node.level, node.module or ""


def test_every_module_imports_only_stdlib_or_package_relative():
    files = sorted(PKG.glob("*.py"))
    assert {f.name for f in files} >= {"__init__.py", "_ledger.py", "_psl_data.py", "_idna_data.py"}
    bad = []
    for f in files:
        for line, level, mod in _imports(f):
            if level >= 2:
                bad.append(f"{f.name}:{line}: from {'.' * level}{mod} — reaches outside the package")
            elif level == 1:
                continue
            elif mod.split(".")[0] not in STDLIB_ALLOWED:
                bad.append(f"{f.name}:{line}: import {mod} — not stdlib-allowed")
    assert not bad, ("xaidr/value_origin must import only the stdlib and itself, or "
                     "paid's vendored copy breaks:\n  " + "\n  ".join(bad))


def test_allowed_modules_really_are_stdlib():
    """The allow-list cannot quietly admit a third-party package."""
    names = getattr(sys, "stdlib_module_names", None)
    if names is None:                 # 3.10: check they import from the stdlib dir
        import importlib
        import sysconfig
        std = Path(sysconfig.get_paths()["stdlib"]).resolve()
        for m in STDLIB_ALLOWED - {"__future__"}:
            mod = importlib.import_module(m)
            f = getattr(mod, "__file__", None)
            assert f is None or std in Path(f).resolve().parents, m
    else:
        assert STDLIB_ALLOWED <= set(names)


def test_no_package_data_outside_python_modules():
    """V-5: paid's wheel ships ``xaidr/**/*.py`` only. A non-.py file in the
    core would ship in open's wheel and silently not in paid's."""
    extra = [p.name for p in PKG.iterdir()
             if p.is_file() and p.suffix != ".py"]
    assert not extra, f"non-.py files in xaidr/value_origin: {extra}"
