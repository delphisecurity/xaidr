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

After building, the archive is handed to `slim validate` when the Splunk
packaging toolkit is on PATH. AppInspect and slim are different validators and
do not cover each other: AppInspect passed this add-on on both tag sets while
slim rejected `app.manifest` outright over an illegal field name. Splunkbase
runs both, so a build that only clears AppInspect can still bounce at upload.

    pip install splunk-packaging-toolkit    # provides `slim`

slim 1.2.8 requires Python >=3.5.1,<3.14. On a 3.14 interpreter pip silently
resolves to 1.0.1 instead, which is a py2-era release whose installer writes to
/usr/local/bin and fails; install it under 3.12/3.13 if that happens.

Validation is skipped with a warning when slim is absent, so it never breaks a
build on a machine that lacks it -- but a slim that runs and fails is fatal.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import shutil
import subprocess
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


def validate(package: Path) -> int:
    """Run `slim validate` on the built archive.

    Returns 0 on success or when slim is not installed, 1 when slim runs and
    rejects the package. Absence is a warning rather than an error so the build
    still works without the toolkit; a rejection is fatal because that is
    precisely the upload failure this is here to catch early.
    """
    slim = shutil.which("slim")
    if slim is None:
        print(
            "  slim   not found -- SKIPPED. `pip install splunk-packaging-toolkit`\n"
            "         (needs Python <3.14). AppInspect does not cover these checks.",
            file=sys.stderr,
        )
        return 0

    print(f"  slim   {slim}")
    result = subprocess.run(
        [slim, "validate", str(package)], capture_output=True, text=True
    )
    # 1.2.8 exits 1 on a rejection, so the returncode alone is enough there. The
    # [ERROR] scan below is belt-and-braces for other versions, not a workaround
    # for a known bug -- slim writes its findings to stderr either way.
    output = result.stdout + result.stderr
    for line in output.splitlines():
        print(f"         {line.strip()}")
    if result.returncode != 0 or "[ERROR]" in output:
        print("  slim   FAILED -- Splunkbase will reject this package", file=sys.stderr)
        return 1
    print("  slim   ok")
    return 0


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
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="skip the `slim validate` pass that runs by default after building",
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
    if args.no_validate:
        return 0
    return validate(args.out.resolve())


if __name__ == "__main__":
    sys.exit(main())
