"""A test must not assume a binary that the machine it runs on happens to have.

This is a gate on the SUITE, not on the package. It exists because the failure
it catches has now shipped three times, every time the same shape: a test
written on macOS asserting something true, through a tool that only the author's
machine had, merged green locally and red on the runner.

  1.17.0  `tests/test_install_hints.py` shelled out to `zsh` to prove an install
          hint is not a shell glob. The property was right. zsh is the default
          macOS shell and is absent from GitHub's Linux runners, so all six
          pytest jobs died on `FileNotFoundError: 'zsh'` and main went red.
  same    the same file did `import tomllib` to read pyproject.toml. tomllib is
          stdlib from 3.11; pyproject declares `requires-python = ">=3.10"`, so
          the two py3.10 jobs failed on `No module named 'tomllib'` as well.
  ee7f901 `tests/test_case_insensitivity_property.py` did
          `import re._parser as sre_parse` to read a regex parse tree. The
          parser is private and it MOVED: `re._parser` is 3.11+, and on 3.10 it
          is the top-level `sre_parse`. Both py3.10 jobs died at collection on
          `No module named 're._parser'; 're' is not a package`. See the
          private-stdlib section below for why neither check above saw it.

None was a wrong assertion. All three were a right assertion asked through the
wrong instrument, and in every case the instrument was invisible in review
because it worked for the person typing it.

The rule below is deliberately narrow: `sys.executable` is free, anything else
must be named here with a reason. Naming is the whole mechanism — it does not
stop a test from using `git`, it stops one from using `git` SILENTLY, which is
the part that reached main. A new external binary fails this test until someone
writes down why the runner will have it.
"""
from __future__ import annotations

import ast
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent

_SUBPROCESS_CALLS = {
    "run", "Popen", "call", "check_call", "check_output",
    "getoutput", "getstatusoutput",
}
_OS_EXEC_CALLS = {"system", "execv", "execvp", "execve", "spawnv", "popen"}

# (file, enclosing function) -> (kind, why).
#
# An entry is a CLAIM about the runner, so it has to say which runner and why —
# "it works on my machine" is the thing this file exists to stop.
#
# The two kinds are not interchangeable, and the distinction is what makes this
# more than a list of names:
#
#   WHICH_GUARDED   the function must resolve the binary through shutil.which()
#                   and skip when it is missing. VERIFIED from the AST below,
#                   not taken on trust — which is the only reason this gate
#                   would have caught 1.17.0. That release's call site had this
#                   same file and this same function name, so an allowlist
#                   keyed on the name alone would have waved it through.
#
#   ALWAYS_PRESENT  the binary is unconditional and a skip would be WRONG,
#                   because skipping would convert a failing invariant into a
#                   silent pass. Rarer, and it has to be argued.
WHICH_GUARDED = "which-guarded"
ALWAYS_PRESENT = "always-present"

_ALLOWED_EXTERNAL_BINARIES = {
    ("test_enforcement_policy_seam.py", "_git_grep"): (ALWAYS_PRESENT, (
        "git. Guaranteed on ubuntu-latest AND guaranteed to have a repo to "
        "read: actions/checkout@v4 IS a git clone, so a runner that got as far "
        "as running pytest has both. Unguarded on purpose — this gate greps "
        "xaidr/ for a forbidden pattern, so skipping it when git is missing "
        "would turn a security invariant into a no-op rather than a failure."
    )),
    ("test_install_hints.py", "test_the_printed_policy_command_is_not_a_glob"): (
        WHICH_GUARDED, (
            "sh/bash/zsh, each resolved through shutil.which() and skipped when "
            "absent. Safe to skip because the shells are redundant: every one "
            "of them expands the glob against the same decoy file, so any "
            "single surviving shell catches the defect. `sh` is asserted "
            "present, so the set can never skip to empty."
        )),
}


def _calls_shutil_which(path, func_name):
    """Does `func_name` in `path` resolve a binary through shutil.which()?"""
    tree = ast.parse((REPO / "tests" / path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != func_name:
            continue
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "which"
            ):
                return True
    return False


def _external_binary_sites():
    """Every subprocess/os-exec call in tests/ that is not the interpreter.

    Returns (relpath, enclosing_function, lineno, argv0_source).
    """
    sites = []
    for path in sorted((REPO / "tests").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))

        # Map each node to its nearest enclosing function.
        enclosing = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    enclosing.setdefault(child, node.name)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not isinstance(fn, ast.Attribute):
                continue
            mod = getattr(fn.value, "id", None)
            if not (
                (mod in ("subprocess", "sp") and fn.attr in _SUBPROCESS_CALLS)
                or (mod == "os" and fn.attr in _OS_EXEC_CALLS)
            ):
                continue

            argv0 = ""
            if node.args:
                first = node.args[0]
                if isinstance(first, ast.List) and first.elts:
                    first = first.elts[0]
                argv0 = ast.unparse(first)

            # The running interpreter is present by construction.
            if "sys.executable" in argv0:
                continue

            sites.append((
                path.name,
                enclosing.get(node, "<module>"),
                node.lineno,
                argv0,
            ))
    return sites


def test_no_test_silently_shells_out_to_an_unlisted_binary():
    """Every non-interpreter subprocess call is declared, with a reason."""
    undeclared = []
    for relpath, func, lineno, argv0 in _external_binary_sites():
        if (relpath, func) not in _ALLOWED_EXTERNAL_BINARIES:
            undeclared.append(
                f"  tests/{relpath}:{lineno} in {func}() runs {argv0}"
            )

    assert not undeclared, (
        "these tests shell out to a binary nobody has promised the CI runner "
        "has:\n" + "\n".join(undeclared) + "\n\n"
        "GitHub's ubuntu-latest has no zsh, and that exact assumption turned "
        "main red for all six pytest jobs in 1.17.0. Either resolve the binary "
        "with shutil.which() and skip when absent (only if the remaining "
        "coverage still catches the defect — a skip that leaves a vacuous "
        "assertion is worse than the crash, because it is green), or add the "
        "site to _ALLOWED_EXTERNAL_BINARIES in tests/test_suite_portability.py "
        "saying why the runner is known to have it."
    )


def test_a_which_guarded_claim_is_actually_which_guarded():
    """The allowlist entry has to be true, not just present.

    This is the clause that would have caught 1.17.0. That release ran
    `subprocess.run([shell, ...])` on a bare "zsh" from the same file and the
    same function that the entry above names, so a name-keyed allowlist would
    have approved it. Requiring the shutil.which() call to be THERE is what
    makes the exemption describe the code rather than the intention.
    """
    unguarded = []
    for (relpath, func), (kind, _why) in _ALLOWED_EXTERNAL_BINARIES.items():
        if kind != WHICH_GUARDED:
            continue
        if not (REPO / "tests" / relpath).exists():
            continue  # test_the_allowlist_has_no_stale_entries reports this
        if not _calls_shutil_which(relpath, func):
            unguarded.append(f"  tests/{relpath}::{func}()")

    assert not unguarded, (
        "these sites are allowlisted as resolving their binary through "
        "shutil.which() and skipping when it is absent, but no which() call "
        "appears in them:\n" + "\n".join(unguarded) + "\n\n"
        "Either restore the guard, or change the entry's kind to "
        "ALWAYS_PRESENT and argue why the runner cannot be without it. An "
        "exemption that outlives the guard it describes is how `zsh` reached "
        "main in 1.17.0."
    )


def test_the_allowlist_has_no_stale_entries():
    """An entry whose call site is gone is a claim about nothing.

    Without this, a site that gets deleted or renamed leaves its permission
    behind, and the next call to appear under that name inherits an exemption
    written for different code.
    """
    live = {(relpath, func) for relpath, func, _, _ in _external_binary_sites()}
    stale = sorted(set(_ALLOWED_EXTERNAL_BINARIES) - live)
    assert not stale, (
        "_ALLOWED_EXTERNAL_BINARIES entries with no matching call site — the "
        "test was renamed or removed and the exemption outlived it: "
        + ", ".join(f"{f}::{fn}" for f, fn in stale)
    )


# Stdlib modules newer than some Python we still claim to support, and the
# version that introduced each. Only modules plausibly reachable from a test
# need listing; the point is to catch the reflex import, not to mirror CPython.
_STDLIB_INTRODUCED_IN = {
    "tomllib": (3, 11),
    "asyncio.taskgroups": (3, 11),
    "zoneinfo": (3, 9),
}

# Imports that are allowed to be newer than the floor because they are guarded
# at the call site rather than at module scope.
_GUARDED_IMPORTS = {
    # tests/test_install_hints.py reaches tomllib through importlib with a
    # tomli fallback and then a parserless scan, so 3.10 never imports it.
    ("test_install_hints.py", "tomllib"),
}


def test_no_test_imports_a_module_newer_than_the_python_we_claim():
    """`import tomllib` is fine on 3.11. pyproject claims 3.10.

    The second half of the 1.17.0 breakage, and unlike the zsh half it is not
    about a binary — so the check above would never have seen it. The shared
    shape is what makes them one defect: an instrument the author's environment
    had and the oldest supported runner did not.

    Only module-scope and function-scope `import X` statements are visible to
    this. An `importlib.import_module` behind a try/except is exactly the fix,
    and it is invisible here by design.
    """
    floor = _requires_python_floor()
    offenders = []

    for path in sorted((REPO / "tests").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                added = _STDLIB_INTRODUCED_IN.get(name)
                if added and added > floor and (path.name, name) not in _GUARDED_IMPORTS:
                    offenders.append(
                        f"  tests/{path.name}:{node.lineno} imports {name} "
                        f"(stdlib from {added[0]}.{added[1]})"
                    )

    assert not offenders, (
        f"these tests import a stdlib module newer than the Python floor "
        f"pyproject.toml declares ({floor[0]}.{floor[1]}), which CI runs a job "
        f"on:\n" + "\n".join(offenders) + "\n\n"
        "Reach it through importlib with a fallback rather than letting "
        "collection die on the oldest supported job."
    )


def _requires_python_floor():
    """The floor pyproject declares, read without assuming a TOML parser."""
    import re

    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'requires-python\s*=\s*["\'][^0-9]*(\d+)\.(\d+)', text)
    assert m, "pyproject.toml has no parseable requires-python floor"
    return int(m.group(1)), int(m.group(2))


# ── private stdlib paths, which MOVE ─────────────────────────────────────────
#
# The third 3.10-specific break in two weeks, and the first that neither check
# above could see. `tests/test_case_insensitivity_property.py` did
# `import re._parser as sre_parse`, which is 3.11+. On 3.10 the parser is the
# top-level `sre_parse`, so both py3.10 jobs died at COLLECTION with
# `ModuleNotFoundError: No module named 're._parser'; 're' is not a package` —
# the file's 68 tests vanished rather than failed.
#
# Why the existing gates missed it, which is the part worth writing down:
#
#   test_no_test_silently_shells_out_to_an_unlisted_binary  is about BINARIES.
#       An import is not a subprocess call; it was never in scope.
#   test_no_test_imports_a_module_newer_than_the_python_we_claim  is keyed on
#       _STDLIB_INTRODUCED_IN, a hand-maintained list of modules that were ADDED.
#       `re._parser` was not added, it was RENAMED — `sre_parse` had been there
#       since 1.6. Nobody adding the import would have thought to list it,
#       because from 3.11's point of view nothing is new.
#
# So the rule here is not another enumeration. It keys on a STRUCTURAL property
# the offending import has and a portable one does not: it reaches into a
# stdlib module's private namespace, and nothing nearby tests the version. That
# is what generalises — a private path carries no compatibility promise, so it
# is exactly the category that moves between the versions our matrix spans, and
# a hand-kept list of which ones moved is always written after the fact.
#
# Scope is tests/ + scripts/ + xaidr/, wider than the binary rule above, because
# a private stdlib import inside the shipped package is strictly worse than one
# in a test: it breaks a 3.10 USER at import time, where no CI job is watching.
# Swept at the time of writing — xaidr/ and scripts/ are clean, and the only
# site in the tree is the one below.

# Stdlib modules that are private by documentation but not by spelling: no
# leading underscore to key on. The sre_* trio are the ones our matrix spans —
# they became re._parser / re._compiler / re._constants in 3.11.
_PRIVATE_BY_DOCUMENTATION = {"sre_parse", "sre_compile", "sre_constants"}

# (file, imported path) -> why this site is allowed to reach a private module.
#
# An entry does NOT exempt the import from being guarded; the guard is verified
# separately from the AST below. It records why a private path is the only way
# to ask the question at all, which is the judgement a reviewer needs and the
# AST cannot make.
_ALLOWED_PRIVATE_STDLIB = {
    ("test_case_insensitivity_property.py", "re._parser"): (
        "the regex PARSE TREE. The census there counts ASCII letters in literal "
        "positions, which is a fact about the parse tree and not about the "
        "pattern text; `re` exposes the compiled Pattern and never the "
        "SubPattern tree, so there is no public spelling. Guarded, with "
        "`sre_parse` on 3.10. Verified to produce the identical census on 3.10, "
        "3.11, 3.12 and 3.14."
    ),
    ("test_case_insensitivity_property.py", "sre_parse"): (
        "the 3.10 half of the same guarded import."
    ),
}


def _is_dunder(part):
    return part.startswith("__") and part.endswith("__")


def _version_guarded_imports(tree):
    """Import nodes sitting under a `sys.version_info` test or an ImportError try.

    Both are real fallbacks. The point of the check is to catch the import that
    has NEITHER — the one that assumes the author's interpreter.
    """
    guarded = set()

    def mark(node):
        for child in ast.walk(node):
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                guarded.add(child)

    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            if "version_info" in ast.unparse(node.test):
                mark(node)
        elif isinstance(node, ast.Try):
            caught = " ".join(
                ast.unparse(h.type) for h in node.handlers if h.type is not None
            )
            if "ImportError" in caught or "ModuleNotFoundError" in caught:
                mark(node)
    return guarded


def _private_stdlib_imports():
    """Every import of a private stdlib path, with whether it is version-guarded.

    Yields (relpath, dotted_path, lineno, guarded). "Private" means the top
    module is stdlib AND either some component of the path starts with an
    underscore, or the module is one of the documented-private names above.
    """
    found = []
    for tree_dir in ("tests", "scripts", "xaidr"):
        root = REPO / tree_dir
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            guarded_nodes = _version_guarded_imports(tree)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    # A relative import is first-party by construction.
                    names = [node.module] if node.module and not node.level else []
                else:
                    continue
                for name in names:
                    parts = name.split(".")
                    if parts[0] not in sys.stdlib_module_names:
                        continue  # first-party or third-party; not our rule
                    # `__future__` and `__main__` are dunders: language
                    # constructs with a stronger stability promise than the
                    # public API, not private implementation. Underscore alone
                    # would flag every `from __future__ import annotations`.
                    private = (
                        any(
                            p.startswith("_") and not _is_dunder(p)
                            for p in parts
                        )
                        or name in _PRIVATE_BY_DOCUMENTATION
                    )
                    if not private:
                        continue
                    found.append((
                        str(path.relative_to(REPO)),
                        name,
                        node.lineno,
                        node in guarded_nodes,
                    ))
    return found


def test_no_module_imports_a_private_stdlib_path_undeclared():
    """A private stdlib path is a promise nobody made. Say why you need it."""
    undeclared = []
    for relpath, name, lineno, _guarded in _private_stdlib_imports():
        key = (pathlib.Path(relpath).name, name)
        if key not in _ALLOWED_PRIVATE_STDLIB:
            undeclared.append(f"  {relpath}:{lineno} imports {name}")

    assert not undeclared, (
        "these modules reach into a private stdlib namespace, which carries no "
        "compatibility promise across the Python versions this project "
        "claims:\n" + "\n".join(undeclared) + "\n\n"
        "`re._parser` is 3.11+; on 3.10 the same parser is the top-level "
        "`sre_parse`, and that one import turned both py3.10 jobs red at "
        "COLLECTION — the tests did not fail, they ceased to exist. Either use "
        "a public API, or add the site to _ALLOWED_PRIVATE_STDLIB in "
        "tests/test_suite_portability.py saying why no public spelling can ask "
        "the question."
    )


def test_every_private_stdlib_import_has_a_version_fallback():
    """Declaring it is not enough — the import has to survive the floor.

    This is the clause that catches the actual defect rather than its paperwork.
    A reviewer approving the entry above is approving the REASON; whether the
    import runs on 3.10 is a fact about the code, and it is read from the AST
    here for the same purpose test_a_which_guarded_claim_is_actually_which_guarded
    serves for binaries. Without it the allowlist would have accepted
    `import re._parser` with a paragraph attached and left py3.10 exactly as red.
    """
    unguarded = []
    for relpath, name, lineno, guarded in _private_stdlib_imports():
        if not guarded:
            unguarded.append(f"  {relpath}:{lineno} imports {name}")

    assert not unguarded, (
        "these private stdlib imports have no version fallback — no enclosing "
        "`sys.version_info` branch and no try/except ImportError:\n"
        + "\n".join(unguarded) + "\n\n"
        "Private stdlib paths move between versions: `sre_parse` became "
        "`re._parser` in 3.11, and the unguarded form raises at collection on "
        f"the {_requires_python_floor()[0]}.{_requires_python_floor()[1]} job "
        "rather than failing a test. Branch on sys.version_info and import the "
        "spelling each version actually has."
    )


def test_the_private_stdlib_allowlist_has_no_stale_entries():
    """An entry whose import is gone would silently permit the next one."""
    live = {(pathlib.Path(r).name, n) for r, n, _, _ in _private_stdlib_imports()}
    stale = sorted(set(_ALLOWED_PRIVATE_STDLIB) - live)
    assert not stale, (
        "_ALLOWED_PRIVATE_STDLIB entries with no matching import — the site was "
        "renamed or removed and the exemption outlived it: "
        + ", ".join(f"{f}::{n}" for f, n in stale)
    )
