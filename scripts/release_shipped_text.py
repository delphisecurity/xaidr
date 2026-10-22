#!/usr/bin/env python3
"""Release step 3a: read what the wheel says (docs/releasing.md).

    python scripts/release_shipped_text.py dist/xaidr-$VERSION-py3-none-any.whl \
        [--phrases "$XAIDR_TRIGGERS"]

Reads every file the wheel ships. A data file is read whole; a ``.py`` file is
read for its PROSE only, its docstrings and its comments, because that is where
an explanation of a fix lives, and code is code. Each is checked for every phrase
in the maintainer-local phrase list (one per line, matched as written) and for
the notice shapes (a security-notice id, a line naming the versions a fix
reaches, a version range, a timing beside an input size).

Exit 0: clean. Exit 1: a hit. Exit 2: the gate cannot run (an empty phrase list,
or an empty wheel), which is never a pass. A hit names the file, the line and the
kind, never the text: the gate exists to keep that text out of a published file,
and its own output must not carry it elsewhere.
"""
from __future__ import annotations

import argparse
import ast
import io
import os
import re
import sys
import tokenize
import zipfile

# The same shapes as before, written with one-character classes so the file does
# not spell the words it looks for.
NOTICE = re.compile(
    r"G[H]SA-[0-9a-z]{4}|C[V]E-[0-9]{4}-|[Aa]ffect[e]d( released)? versions?"
    r"|[0-9]+\.[0-9]+\.[0-9]+\*{0,2} through|[0-9.]+ ?m?s (on|at) (a )?[0-9,]+[- ]chars?"
    r"|-char trigger")


def _prose(source: str):
    """(line, text) for every docstring and comment of a Python source."""
    out = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [(i + 1, line) for i, line in enumerate(source.splitlines())]
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body:
            first = body[0]
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                for k, line in enumerate(first.value.value.splitlines()):
                    out.append((first.lineno + k, line))
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                out.append((tok.start[0], tok.string))
    except (tokenize.TokenError, IndentationError):
        pass
    return out


def scan(wheel: str, phrases: list):
    hits, data_files, py_files = [], 0, 0
    with zipfile.ZipFile(wheel) as z:
        for name in z.namelist():
            if name.endswith("/"):
                continue
            text = z.read(name).decode("utf-8", errors="replace")
            if name.endswith(".py"):
                py_files += 1
                lines = _prose(text)
            else:
                data_files += 1
                lines = [(i + 1, line) for i, line in enumerate(text.splitlines())]
            for lineno, line in lines:
                for k, phrase in enumerate(phrases):
                    if phrase in line:
                        hits.append((name, lineno, f"phrase #{k + 1}"))
                if NOTICE.search(line):
                    hits.append((name, lineno, "notice shape"))
    return hits, data_files, py_files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("wheel")
    ap.add_argument("--phrases", default=os.environ.get("XAIDR_TRIGGERS", ""))
    args = ap.parse_args(argv)
    try:
        with open(args.phrases, encoding="utf-8") as fh:
            phrases = [p.strip() for p in fh if p.strip()]
    except OSError:
        phrases = []
    hits, data_files, py_files = scan(args.wheel, phrases) if phrases else ([], 0, 0)
    if not phrases or data_files + py_files == 0:
        print(f"GATE CANNOT RUN: phrases={len(phrases)} files={data_files + py_files}")
        return 2
    print(f"scanned {data_files} data file(s) and the docstrings and comments of "
          f"{py_files} .py file(s) for {len(phrases)} phrase(s) and the notice shapes")
    for name, lineno, kind in hits:
        print(f"{name}:{lineno} {kind}")
    if hits:
        print(f"SHIPPED TEXT: RED ({len(hits)} hit(s))")
        return 1
    print("SHIPPED TEXT: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
