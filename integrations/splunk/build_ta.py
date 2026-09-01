#!/usr/bin/env python3
"""Build TA-xaidr.tar.gz reproducibly.

Byte-identical output from the same source tree, on any machine, in any
checkout. Run it twice, get the same sha256; that is the point.

    python3 integrations/splunk/build_ta.py
    python3 integrations/splunk/build_ta.py --out dist/TA-xaidr.tar.gz

Three things vary between builds if you let them, and all three are pinned here:

1. **The gzip header timestamp.** gzip stamps the compression time into the
   header by default, so two builds of identical bytes differ. `gzip -n` is the
   CLI fix; `GzipFile(mtime=0)` is this one.
2. **Per-file mtimes.** tar records them, and a fresh `git clone` sets every
   file to checkout time. This is the one that bites, because it is invisible
   locally: rebuilding from a tree you already had preserves mtimes and the
   hash looks stable, then CI clones fresh and the hash moves. Every member is
   stamped `SOURCE_DATE_EPOCH` instead.
3. **Walk order, uid/gid, and mode.** `os.walk` order is filesystem-dependent,
   and the builder's own uid/gid would otherwise land in the archive. Members
   are sorted, owned by root:root with empty owner names, and normalised to
   0644 / 0755.

Set SOURCE_DATE_EPOCH to override the timestamp. The default is fixed rather
than "now" so that the default build is the reproducible one -- a default of
`time.time()` would put the trap back.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import sys
import tarfile
from pathlib import Path

#: 2026-09-01T00:00:00Z. Arbitrary but fixed: what matters is that it does not
#: move between builds. Bump it on release if you want the archive to carry a
#: meaningful date; never make it derive from the clock.
DEFAULT_SOURCE_DATE_EPOCH = 1788307200

APP_DIR_NAME = "TA-xaidr"

#: Never package these. Chiefly macOS metadata (AppleDouble `._*` forks and
#: `.DS_Store`), which AppInspect flags and which carry no content.
EXCLUDE_NAMES = {".DS_Store", "__pycache__", ".gitignore", ".gitkeep"}
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".orig", ".rej", ".swp")


def _excluded(name: str) -> bool:
    return (
        name in EXCLUDE_NAMES
        or name.startswith("._")
        or name.endswith(EXCLUDE_SUFFIXES)
    )


def collect(app_root: Path) -> list[tuple[Path, str]]:
    """Return (absolute path, archive name) pairs, sorted by archive name.

    Directories are included as their own members so the archive carries
    explicit, mode-normalised entries rather than whatever the extractor
    invents from the file paths.
    """
    members: list[tuple[Path, str]] = []
    for path in sorted(app_root.rglob("*")):
        if any(_excluded(part) for part in path.relative_to(app_root).parts):
            continue
        if not (path.is_dir() or path.is_file()):
            continue  # symlinks, sockets, devices: not for a config-only TA
        arcname = f"{APP_DIR_NAME}/{path.relative_to(app_root).as_posix()}"
        members.append((path, arcname))
    return sorted(members, key=lambda m: m[1])


def build(app_root: Path, out_path: Path, epoch: int) -> str:
    """Write the archive and return its sha256."""
    members = collect(app_root)
    if not members:
        raise SystemExit(f"error: no files found under {app_root}")

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        root = tarfile.TarInfo(APP_DIR_NAME)
        root.type, root.mode = tarfile.DIRTYPE, 0o755
        for info in (root,):
            info.mtime, info.uid, info.gid = epoch, 0, 0
            info.uname = info.gname = ""
        tar.addfile(root)

        for path, arcname in members:
            info = tar.gettarinfo(str(path), arcname=arcname)
            info.mtime, info.uid, info.gid = epoch, 0, 0
            info.uname = info.gname = ""
            info.mode = 0o755 if info.isdir() else 0o644
            if info.isdir():
                tar.addfile(info)
            else:
                with open(path, "rb") as fh:
                    tar.addfile(info, fh)

    # mtime=0 is the API equivalent of `gzip -n`: no name, no timestamp.
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=0
    ) as gz:
        gz.write(raw.getvalue())
    blob = compressed.getvalue()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(blob)
    return hashlib.sha256(blob).hexdigest()


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--app-root",
        type=Path,
        default=here / APP_DIR_NAME,
        help=f"source tree to package (default: {APP_DIR_NAME}/ beside this script)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=here.parents[1] / "dist" / f"{APP_DIR_NAME}.tar.gz",
        help="output path (default: dist/TA-xaidr.tar.gz at the repo root)",
    )
    args = parser.parse_args(argv)

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", DEFAULT_SOURCE_DATE_EPOCH))
    app_root = args.app_root.resolve()
    if not (app_root / "default" / "app.conf").is_file():
        raise SystemExit(f"error: {app_root} does not look like a Splunk app")

    digest = build(app_root, args.out.resolve(), epoch)
    size = args.out.resolve().stat().st_size
    print(f"{args.out.resolve()}")
    print(f"  sha256 {digest}")
    print(f"  bytes  {size}")
    print(f"  epoch  {epoch}  (SOURCE_DATE_EPOCH to override)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
