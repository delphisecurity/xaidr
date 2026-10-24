"""The release disclosure scan: outgoing commit messages and added lines.

    python scripts/disclosure_scan.py --phrases FILE [--phrases FILE ...]
                                      [--base REF] [--public REF ...]

Each ``--phrases`` file holds one phrase per line, matched case-insensitively
anywhere in a line; the phrases are never printed. The scan reads every commit
in ``BASE..HEAD`` that no ``--public`` ref already holds (its message, less
``Signed-off-by`` and ``Co-Authored-By`` trailers) and every line ``BASE..HEAD``
adds that is not already in the same file on a ``--public`` ref. A hit prints
the commit or the file and the line, and the run exits 1; no hit exits 0. No
phrase, or a git error, is a refusal (exit 2), never a pass.

ONE EXEMPTION. A file under ``tests/published_vectors/`` that
``tests/published_vectors/MANIFEST.json`` lists, while its bytes at HEAD match the
manifest's sha256, is an upstream project's file copied byte for byte (a
published test suite, its licence), and its lines are not ours to reword, so
they are not scanned. A file there with one byte changed, a file there the
manifest does not list (a README, notes, a script), and every commit message are
scanned as anything else is.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys

VENDORED_DIR = "tests/published_vectors/"
MANIFEST = VENDORED_DIR + "MANIFEST.json"
_TRAILER = re.compile(r"^\s*(Signed-off-by|Co-Authored-By):", re.I)


def _git(*args, check=False) -> bytes:
    r = subprocess.run(["git", *args], capture_output=True)
    if check and r.returncode:
        print(f"REFUSING: git {' '.join(args)}: {r.stderr.decode(errors='replace').strip()}")
        raise SystemExit(2)
    return r.stdout


def exempt(path: str, data: bytes | None, manifest: dict | None) -> bool:
    """True iff ``path`` is a vendored file whose bytes match the manifest."""
    if not path.startswith(VENDORED_DIR) or data is None or not manifest:
        return False
    rel = path[len(VENDORED_DIR):]
    want = {f["path"]: f["sha256"] for f in manifest.get("files", ())}.get(rel)
    return want is not None and hashlib.sha256(data).hexdigest() == want


def matcher(phrases):
    phrases = [p for p in phrases if p]
    if not phrases:
        print("REFUSING: no phrase to scan for")
        raise SystemExit(2)
    return re.compile("|".join(re.escape(p) for p in phrases), re.I)


def scan(base: str, public: list, pat) -> list:
    """[(where, what)] for every hit in BASE..HEAD."""
    hits = []
    commits = _git("rev-list", f"{base}..HEAD", "--not", *public, check=True).decode().split()
    for c in commits:
        for line in _git("log", "-1", "--format=%B", c).decode("utf-8", "replace").splitlines():
            if not _TRAILER.match(line) and pat.search(line):
                hits.append((f"commit {c[:10]}", line.strip()[:160]))
    raw = _git("show", f"HEAD:{MANIFEST}")
    try:
        manifest = json.loads(raw) if raw else None
    except ValueError:
        manifest = None
    known: dict = {}
    current, skip = None, False
    for line in _git("diff", "-U0", base, "HEAD").decode("utf-8", "replace").splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
            skip = current is not None and exempt(current, _git("show", f"HEAD:{current}"),
                                                  manifest)
            continue
        if current is None or skip or not line.startswith("+"):
            continue
        text = line[1:]
        if any(text in known.setdefault((current, ref), set(
                _git("show", f"{ref}:{current}").decode("utf-8", "replace").splitlines()))
               for ref in public):
            continue
        if pat.search(text) and not _TRAILER.match(text):
            hits.append((current, text.strip()[:160]))
    return hits


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--phrases", action="append", default=[], required=True)
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--public", action="append", default=[])
    a = ap.parse_args(argv)
    phrases = []
    for path in a.phrases:
        with open(path, encoding="utf-8") as fh:
            phrases += [p.strip() for p in fh if p.strip()]
    hits = scan(a.base, a.public, matcher(phrases))
    for where, what in hits:
        print(f"HIT {where}: {what}")
    print(f"DISCLOSURE SCAN: {'RED' if hits else 'clean'} ({len(hits)} hit(s))")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
