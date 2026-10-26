"""The release disclosure scan exempts a vendored file only while its bytes are
upstream's (scripts/disclosure_scan.py).

Each case builds a git repository in a temporary directory: a base commit, then
an outgoing commit, and the scan runs over base..HEAD with a phrase that occurs
in the files. A file under tests/published_vectors/ that MANIFEST.json lists,
with its sha256, is skipped; the same file with one byte changed is scanned, a
file of ours in that folder is scanned, and commit messages are always scanned.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "scripts" / "disclosure_scan.py"
PHRASE = "quartzfrog"


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.example",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.example",
                        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
                        "HOME": str(repo)})


def _repo(tmp_path, files, *, manifest_bytes=None, message="add files"):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README").write_text("base\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "tag", "base")
    vendored = repo / "tests" / "published_vectors"
    for rel, data in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    listed = manifest_bytes if manifest_bytes is not None else {}
    vendored.mkdir(parents=True, exist_ok=True)
    (vendored / "MANIFEST.json").write_text(json.dumps({"files": [
        {"path": rel, "url": "https://example.org/" + rel, "version": "v1",
         "sha256": hashlib.sha256(data).hexdigest()} for rel, data in listed.items()]}))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    phrases = tmp_path / "phrases.txt"
    phrases.write_text(PHRASE + "\n")
    return repo, phrases


def _scan(repo, phrases):
    r = subprocess.run([sys.executable, str(SCAN), "--phrases", str(phrases), "--base", "base"],
                       cwd=repo, capture_output=True, text=True)
    return r.returncode, r.stdout


UPSTREAM = b"Licence granted; see the " + PHRASE.encode() + b" note.\n"


def test_a_vendored_file_matching_its_manifest_entry_is_not_scanned(tmp_path):
    repo, phrases = _repo(
        tmp_path, {"tests/published_vectors/upstream/suite.txt": UPSTREAM},
        manifest_bytes={"upstream/suite.txt": UPSTREAM})
    code, out = _scan(repo, phrases)
    assert code == 0 and "clean" in out, out


def test_a_vendored_file_with_one_byte_changed_is_scanned(tmp_path):
    changed = UPSTREAM.replace(b"granted", b"grantee")
    repo, phrases = _repo(
        tmp_path, {"tests/published_vectors/upstream/suite.txt": changed},
        manifest_bytes={"upstream/suite.txt": UPSTREAM})
    code, out = _scan(repo, phrases)
    assert code == 1 and "tests/published_vectors/upstream/suite.txt" in out, out


def test_a_file_of_ours_in_the_vendored_folder_is_scanned(tmp_path):
    repo, phrases = _repo(
        tmp_path, {"tests/published_vectors/upstream/suite.txt": UPSTREAM,
                   "tests/published_vectors/README.md": b"notes: " + PHRASE.encode() + b"\n"},
        manifest_bytes={"upstream/suite.txt": UPSTREAM})
    code, out = _scan(repo, phrases)
    assert code == 1 and "tests/published_vectors/README.md" in out, out
    assert "upstream/suite.txt" not in out, out


def test_a_commit_message_is_always_scanned(tmp_path):
    repo, phrases = _repo(
        tmp_path, {"tests/published_vectors/upstream/suite.txt": UPSTREAM},
        manifest_bytes={"upstream/suite.txt": UPSTREAM}, message=f"vendor the {PHRASE} suite")
    code, out = _scan(repo, phrases)
    assert code == 1 and "commit" in out, out


def test_a_file_outside_the_folder_with_the_same_bytes_is_scanned(tmp_path):
    repo, phrases = _repo(tmp_path, {"docs/suite.txt": UPSTREAM},
                          manifest_bytes={"upstream/suite.txt": UPSTREAM})
    code, out = _scan(repo, phrases)
    assert code == 1 and "docs/suite.txt" in out, out


@pytest.mark.parametrize("phrases", ["", "\n\n"])
def test_no_phrase_is_a_refusal(tmp_path, phrases):
    repo, path = _repo(tmp_path, {"docs/x.txt": b"x\n"})
    path.write_text(phrases)
    code, out = _scan(repo, path)
    assert code not in (0, 1), out


# ── a public ref: lines it already holds are not outgoing ───────────────────
def _public_repo(tmp_path):
    """base, then a public commit adding one file, then an outgoing commit adding
    lines to it and a second file. Hits: the outgoing lines with the phrase that
    the public ref does not hold, in both files."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README").write_text("base\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "tag", "base")
    (repo / "docs").mkdir()
    old = [f"line {i} {PHRASE}" if i % 7 == 0 else f"line {i}" for i in range(60)]
    (repo / "docs" / "a.txt").write_text("\n".join(old) + "\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "public")
    _git(repo, "tag", "public")
    new = old + [f"more {i} {PHRASE}" if i % 5 == 0 else f"more {i}" for i in range(40)]
    (repo / "docs" / "a.txt").write_text("\n".join(new) + "\n")
    (repo / "docs" / "b.txt").write_text(f"fresh {PHRASE}\nplain\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "outgoing")
    phrases = tmp_path / "phrases.txt"
    phrases.write_text(PHRASE + "\n")
    return repo, phrases


def test_a_public_ref_holds_back_its_own_lines_and_only_those(tmp_path):
    """The positive control for the per-file cache: the hits are exactly the
    outgoing lines the public ref does not hold, named in full. The same repository
    gives these same lines with the scan as it was before the cache (checked when
    the cache was added, 2026-10-24)."""
    repo, phrases = _public_repo(tmp_path)
    r = subprocess.run([sys.executable, str(SCAN), "--phrases", str(phrases), "--base", "base",
                        "--public", "public"], cwd=repo, capture_output=True, text=True)
    hits = sorted(line for line in r.stdout.splitlines() if line.startswith("HIT "))
    assert r.returncode == 1, r.stdout
    assert hits == sorted([f"HIT docs/a.txt: more {i} {PHRASE}" for i in range(0, 40, 5)]
                          + [f"HIT docs/b.txt: fresh {PHRASE}"]), r.stdout


def test_a_public_refs_copy_of_a_file_is_read_once(tmp_path, monkeypatch):
    """One ``git show <ref>:<file>`` per file and public ref, not one per added line."""
    import importlib.util
    repo, _ = _public_repo(tmp_path)
    spec = importlib.util.spec_from_file_location("disclosure_scan", SCAN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    shows, real = [], mod._git

    def counting(*args, check=False):
        if args[0] == "show" and args[1].startswith("public:"):
            shows.append(args[1])
        return real(*args, check=check)
    monkeypatch.setattr(mod, "_git", counting)
    monkeypatch.chdir(repo)
    hits = mod.scan("base", ["public"], mod.matcher([PHRASE]))
    assert len(hits) == 9, hits
    assert sorted(shows) == ["public:docs/a.txt", "public:docs/b.txt"], (
        f"{len(shows)} reads of the public ref's files for 2 files: {shows[:5]}")
