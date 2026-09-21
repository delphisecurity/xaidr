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
  PR #24  `scripts/policy_width_report.py` wrote
          `f"{f'{r['attacks_gated']} of {r['attacks_n']}':>18}"`. The
          replacement expression reuses the `'` that opened the f-string, which
          PEP 701 legalised in 3.12 and 3.10 and 3.11 reject at PARSE time. Both
          py3.10 jobs and both py3.11 jobs died at collection in 20 seconds on
          `SyntaxError: f-string: unmatched '['`. See the f-string section at
          the bottom for why none of the three checks above could see it.

None was a wrong assertion. All four were a right assertion asked through the
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
    ("test_install_hints.py", "_grepped_hint_files"): (WHICH_GUARDED, (
        "grep, resolved through shutil.which() and then ASSERTED present "
        "rather than skipped. POSIX requires it and every platform this "
        "package supports has it, so absence is not a portability case, it is "
        "a broken environment — the same call `sh` gets in the shell test "
        "above. It is which-guarded anyway so the failure names the missing "
        "binary instead of surfacing as FileNotFoundError from subprocess. "
        "A skip here would be WRONG: this is the second, independent "
        "enumeration that catches the scan going short (nine hint sites "
        "reported when there were ten), and without it the Python walk agrees "
        "only with itself."
    )),
    ("test_battery_case_ids.py", "_walk"): (ALWAYS_PRESENT, (
        "git, for the same reason as _tracked_files below, and with the same "
        "degradation: a non-zero returncode or empty stdout falls back to a "
        "filesystem walk of the repo root rather than raising or returning "
        "nothing. That path is for an EXTRACTED SDIST — this branch ships "
        "tests/ inside it — where there is no index to read and also none of "
        "the gitignored run outputs the index was excluding, so the two "
        "scopes coincide there. OSError and SubprocessError are both caught, "
        "so a runner with no git binary takes the fallback instead of "
        "erroring, and the `scanned` fixture asserts >50 files either way so "
        "neither path can degrade into a green empty scan."
    )),
    ("test_sdist_contents.py", "_tracked_files"): (ALWAYS_PRESENT, (
        "git, for the same reason as _git_grep above: actions/checkout@v4 IS a "
        "git clone, so a runner that reached pytest has both the binary and a "
        "repository. Unguarded by shutil.which() but not unguarded in effect — "
        "a non-zero returncode returns None and the caller skips with a note "
        "that only the explicit floor was checked. That path exists for an "
        "EXTRACTED SDIST, where there is genuinely no index to enumerate, and "
        "the floor is a non-empty list of named pool files so the skip narrows "
        "the check rather than emptying it."
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


# ── syntax, which is not an import and not a binary ──────────────────────────
#
# The fourth 3.10-specific break in two weeks, and the first that none of the
# three checks above could see even in principle.
# `scripts/policy_width_report.py` wrote
#
#     f"{f'{r['attacks_gated']} of {r['attacks_n']}':>18}"
#
# The inner replacement expression reuses the `'` that opened the f-string it
# sits in. PEP 701 legalised that in 3.12; on 3.10 and 3.11 the tokenizer ends
# the string at that quote and the file does not parse. Four of the six pytest
# jobs died at COLLECTION on `SyntaxError: f-string: unmatched '['`, which is
# the `re._parser` consequence again — the tests did not fail, they ceased to
# exist.
#
# DOES A SYNTAX CHECK BELONG IN THIS FILE? Yes, and the argument is the thesis
# of the docstring at the top: an instrument the author's interpreter had and
# the oldest supported runner did not. A 3.12-only spelling is that exactly.
# Nothing above reaches it, and not by oversight —
#
#   the binary rule   is about subprocess argv. Syntax is not a call.
#   the new-stdlib rule  is keyed on _STDLIB_INTRODUCED_IN, a list of modules
#       that were ADDED. No module is involved here at all.
#   the private-stdlib rule  keys on a dotted import path. Same.
#
# All three ask their question about the AST. To have an AST you must first
# parse, and parsing is the step that failed.
#
# THE TRAP, AND WHY THIS IS TWO TESTS. The obvious gate — compile() every file
# under the running interpreter — is EXACT on the 3.10 job and VACUOUS on every
# other one, because on 3.12 the offending file compiles fine. A gate that can
# only fire where the build is already red is the passes-vacuously shape this
# workstream keeps producing: it would report coverage on four of six jobs while
# performing none, and it would give a developer on 3.12 — which is every
# developer here — no local signal at all. That is the gap that let this reach
# CI in the first place.
#
# `ast.parse(src, feature_version=(3, 10))` does NOT close it. Measured on
# 3.12.2 and 3.14.5 against the pre-fix file: it parses clean at every
# feature_version, including (3, 10). The flag does not reach the f-string
# tokenizer.
#
# So the two halves below split the job along the line the interpreter draws:
#
#   test_every_first_party_file_parses_...   compile(). Complete at the floor,
#       where it is the whole answer, and it covers files that NO test currently
#       parses — the defect was only visible at collection because
#       test_report_provenance.py happens to ast.parse() every script.
#   test_no_f_string_uses_syntax_the_floor_rejects   an AST scan for the PEP 701
#       relaxations specifically. This is the half that bites on 3.11, 3.12 and
#       3.14, where compile() cannot see the defect. On 3.10 it is the redundant
#       one. Between them no job in the matrix is vacuous.
#
# Scope is every first-party .py in the repo, derived rather than listed. The
# sweep has no allowlist to keep in sync, so breadth is free — and three of the
# four Python roots here (`xaidr`, `scripts`, `tests`, plus `repro_audit.py`)
# ship inside the sdist, where a file that will not parse on 3.10 is a broken
# artifact in a 3.10 user's hands with no CI job watching.

_SKIP_DIRS = {"build", "dist", "__pycache__", "node_modules", "site-packages"}


def _first_party_python_files():
    """Every .py in the repo that is ours, derived from the tree."""
    out = []
    for path in sorted(REPO.rglob("*.py")):
        rel = path.relative_to(REPO)
        if any(p.startswith(".") or p in _SKIP_DIRS for p in rel.parts[:-1]):
            continue
        out.append(path)
    return out


def test_the_syntax_sweep_scope_is_not_empty():
    """A derived scope can derive to nothing, and that must be red, not green.

    Both tests below are a loop over `_first_party_python_files()`. If the
    rglob, the `.`-prefix filter or `_SKIP_DIRS` ever swallows the tree, the
    loops run zero times and pytest reports two passes — a check constraining
    nothing, reported as coverage. 184 files matched when this was written; the
    floor is well under that so ordinary churn does not trip it.
    """
    found = _first_party_python_files()
    assert len(found) >= 100, (
        f"only {len(found)} first-party .py file(s) found under {REPO}. The "
        f"sweep below is a loop over this list, so a scope this small means the "
        f"enumeration broke, not that the files went away."
    )


def test_every_first_party_file_parses_under_the_running_interpreter():
    """Nothing in the tree may fail to PARSE on the Python running this test.

    On the floor job this is the complete check and the whole point: CI runs a
    py3.10 job, so a 3.12-only spelling anywhere in the tree fails here by name
    instead of detonating at collection. Above the floor it is a tautology —
    which is what the f-string test below exists to cover.
    """
    floor = _requires_python_floor()
    running = sys.version_info[:2]
    broken = []

    for path in _first_party_python_files():
        source = path.read_text(encoding="utf-8")
        try:
            compile(source, str(path), "exec")
        except SyntaxError as exc:
            broken.append(
                f"  {path.relative_to(REPO)}:{exc.lineno}: {exc.msg}\n"
                f"      {(exc.text or '').strip()}"
            )

    assert not broken, (
        f"these files do not parse under the Python running this test "
        f"({running[0]}.{running[1]}), while pyproject.toml claims "
        f"{floor[0]}.{floor[1]} and CI runs a job on it:\n"
        + "\n".join(broken) + "\n\n"
        "A file that will not parse does not fail its tests, it DELETES them — "
        "collection dies and every case in the module silently stops existing. "
        "PEP 701 relaxed f-string quoting in 3.12, so a spelling that is fine "
        "in your editor can be a SyntaxError on the oldest job; see the "
        "f-string test below for the specific constructs."
    )


# The PEP 701 relaxations, as properties of a replacement expression's SOURCE
# TEXT. Deliberately not an enumeration of "bad spellings": these are the rules
# the pre-3.12 tokenizer enforced, so the list is closed by the language rather
# than by whoever last got bitten.
#
# NOT included, and checked rather than assumed: `#` inside a replacement
# expression. It reads like a fourth relaxation, but measured on 3.10.21,
# `f"{s.replace('#','')}"` compiles clean — the restriction never applied inside
# a nested string literal, which is the only way a `#` plausibly appears here.
# Flagging it would have been a false positive on legal code.
_QUOTE_PREFIXES = "fFrRbBuU"


def _opening_quote(literal_source):
    """The quote that opens an f-string literal, prefix skipped."""
    i = 0
    while i < len(literal_source) and literal_source[i] in _QUOTE_PREFIXES:
        i += 1
    for quote in ('"""', "'''", '"', "'"):
        if literal_source.startswith(quote, i):
            return quote
    return None


def _pep701_only_fstrings(source):
    """(lineno, expression_source, why) for each pre-3.12-illegal f-string field.

    Reads the SOURCE TEXT of each replacement expression rather than its AST
    shape, because every rule here is about characters the old tokenizer could
    not see past.
    """
    found = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        literal = ast.get_source_segment(source, node)
        if not literal:
            continue
        quote = _opening_quote(literal)
        if not quote:
            continue
        for part in node.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            expr = ast.get_source_segment(source, part.value)
            if not expr:
                continue
            why = []
            if quote[0] in expr:
                why.append(
                    f"reuses the {quote[0]!r} that opened the f-string"
                )
            if "\\" in expr:
                why.append("contains a backslash")
            if len(quote) == 1 and "\n" in expr:
                why.append("spans lines inside a singly-quoted f-string")
            if why:
                found.append((part.value.lineno, expr, "; ".join(why)))
    return found


def test_no_f_string_uses_syntax_the_floor_rejects():
    """The half that bites ABOVE the floor, where compile() has nothing to say.

    On 3.12+ the offending file parses, so the test above passes and the py3.12
    jobs stay green while py3.10 and py3.11 are dead at collection. That is the
    review-time gap: every developer here runs 3.12. This reads the parse tree
    the newer interpreter was willing to build and asks whether the older one
    would have been, which is a question compile() cannot be made to ask —
    `ast.parse(feature_version=(3, 10))` parses the pre-fix file clean on both
    3.12.2 and 3.14.5.

    On 3.10 and 3.11 this is the redundant one: an offending file raises
    SyntaxError from `ast.parse` here and from `compile` above, and the test
    above is the one that reports it usefully.
    """
    floor = _requires_python_floor()
    offenders = []

    for path in _first_party_python_files():
        source = path.read_text(encoding="utf-8")
        try:
            hits = _pep701_only_fstrings(source)
        except SyntaxError:
            continue  # the compile() sweep above owns this file's failure
        for lineno, expr, why in hits:
            offenders.append(
                f"  {path.relative_to(REPO)}:{lineno}: {{{expr}}} — {why}"
            )

    assert not offenders, (
        f"these f-string replacement expressions use syntax PEP 701 legalised "
        f"in 3.12, and pyproject.toml claims {floor[0]}.{floor[1]}:\n"
        + "\n".join(offenders) + "\n\n"
        "Pre-3.12 the tokenizer ends the string at the reused quote, so the "
        "FILE does not parse and collection takes every test in it down — "
        "`f\"{f'{r['k']}'}\"` is `SyntaxError: f-string: unmatched '['` on 3.10 "
        "and 3.11. Bind the value to a name first, or use the other quote "
        "character. This test is the one that can tell you so from 3.12, where "
        "the code you just wrote compiles."
    )
