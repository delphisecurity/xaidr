#!/usr/bin/env python3
"""Fail if a version tag exists on GitHub with no published release object.

WHY THIS READS THE API AND NOT THE TREE.

Every other guard in this repository proves the tree is self-consistent. This
one cannot, because the thing it is checking does not live in the tree: a
release object is server-side state, and the failure it exists to catch --
fifteen tags and zero releases, which is the state this repo was in on
2026-09-09 -- is invisible to `git tag`, to pytest, and to every CI job that
only ever looks at a checkout. So BOTH sides of the comparison are fetched from
GitHub:

    tags     GET /repos/{repo}/tags
    releases GET /repos/{repo}/releases

`git tag` is deliberately NOT used. It is the tempting shortcut and it would
break the property that makes this check worth having: a checkout can be stale,
shallow, or missing tags entirely (`actions/checkout` fetches none by default),
and a gate that compares a local list against a remote one is measuring the
runner, not the repository.

WHAT COUNTS AS A RELEASE. A published one. A DRAFT DOES NOT COUNT, and this is
the discriminating case: a draft is exactly what an interrupted release leaves
behind, it is invisible to everyone who is not a maintainer, and it notifies
nobody. Drafts are filtered explicitly rather than relying on the token's scope
to hide them, because a token with `contents: write` can see them.

THE FLOOR. Tags below `--floor` are reported and skipped, not silently ignored.
The release process that requires a release object took effect at v1.10.0 (see
docs/releasing.md); tags below it predate the policy. A floor is used rather
than a list of grandfathered tags on purpose -- an exception list never shrinks
and eventually constrains nothing, whereas a floor is monotone: every tag this
project will ever cut again is above it.

Usage:
    python scripts/release_objects_gate.py                    # sweep every tag >= floor
    python scripts/release_objects_gate.py --tag v1.15.0      # one tag (the tag-push job)
    python scripts/release_objects_gate.py --tag v1.15.0 --wait-seconds 600
    python scripts/release_objects_gate.py --floor v1.0.0     # include the pre-policy tags

Exit 0 = every tag in scope has a published release. Exit 1 = at least one does
not, and each is named. Exit 2 = the check could not run (network, auth, bad
argument); that is NOT a pass, and it is a distinct code so CI cannot confuse
"nothing is missing" with "nothing was checked".

Auth is optional for a public repo but strongly preferred: unauthenticated
GitHub API calls are rate-limited to 60/hour per IP. Reads GH_TOKEN or
GITHUB_TOKEN from the environment. Requires only `contents: read`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
DEFAULT_REPO = "delphisecurity/xaidr"

# The release cut at which docs/releasing.md's process took effect.
DEFAULT_FLOOR = "v1.10.0"

# Version tags only. A tag that is not a release tag (a scratch tag, a moved
# pointer) is not something this gate has an opinion about.
TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


class CheckError(RuntimeError):
    """The check could not be run. Distinct from 'the check failed'."""


# ── the GitHub side ─────────────────────────────────────────────────────────


def _get(path: str, token: str | None):
    req = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "xaidr-release-objects-gate",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:400]
        raise CheckError(f"GET {path} -> HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise CheckError(f"GET {path} -> {exc.reason}") from exc


def _paginate(path: str, token: str | None, cap: int = 20):
    """Every page, not the first. The default page size is 30; this project
    already has 15 tags and will pass 30 without anyone noticing, and a gate
    that silently stops at page one would start passing at exactly the moment
    it has enough history to matter."""
    out = []
    for page in range(1, cap + 1):
        sep = "&" if "?" in path else "?"
        chunk = _get(f"{path}{sep}per_page=100&page={page}", token)
        if not isinstance(chunk, list):
            raise CheckError(f"GET {path} returned {type(chunk).__name__}, expected a list")
        out.extend(chunk)
        if len(chunk) < 100:
            return out
    raise CheckError(f"GET {path} exceeded {cap} pages; refusing to report a partial list")


def fetch_tags(repo: str, token: str | None) -> list[str]:
    return [t["name"] for t in _paginate(f"/repos/{repo}/tags", token)]


def fetch_published_release_tags(repo: str, token: str | None) -> set[str]:
    return {
        r["tag_name"]
        for r in _paginate(f"/repos/{repo}/releases", token)
        if not r.get("draft", False)
    }


# ── the comparison, pure so it can be tested without a network ──────────────


def version_key(tag: str):
    m = TAG_RE.match(tag)
    return tuple(int(p) for p in m.groups()) if m else None


def audit(tags, released, floor, only_tag=None):
    """Return (missing, covered, skipped_below_floor, ignored_non_version).

    `missing` is the finding: version tags in scope with no published release.
    The other three are returned so the caller can PRINT what it did not check.
    A gate that reports only its findings reads as full coverage while
    performing whatever coverage its filters happen to allow.
    """
    floor_key = version_key(floor)
    if floor_key is None:
        raise CheckError(f"--floor must look like vMAJOR.MINOR.PATCH, got {floor!r}")

    missing, covered, skipped, ignored = [], [], [], []
    for tag in tags:
        if only_tag is not None and tag != only_tag:
            continue
        key = version_key(tag)
        if key is None:
            ignored.append(tag)
        elif key < floor_key:
            skipped.append(tag)
        elif tag in released:
            covered.append(tag)
        else:
            missing.append(tag)

    sort = lambda ts: sorted(ts, key=version_key)  # noqa: E731
    return sort(missing), sort(covered), sort(skipped), sorted(ignored)


# ── reporting ───────────────────────────────────────────────────────────────


def run_once(repo, token, floor, only_tag):
    tags = fetch_tags(repo, token)
    if only_tag is not None and only_tag not in tags:
        raise CheckError(
            f"{only_tag} is not a tag on {repo}. The gate checks the REMOTE tag "
            f"list, so a tag that exists only locally has not been pushed."
        )
    released = fetch_published_release_tags(repo, token)
    return audit(tags, released, floor, only_tag), len(tags), len(released)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPO))
    ap.add_argument("--floor", default=DEFAULT_FLOOR)
    ap.add_argument("--tag", default=None, help="check one tag instead of sweeping all")
    ap.add_argument(
        "--wait-seconds",
        type=int,
        default=0,
        help=(
            "poll until the release appears, then pass. For the tag-push job: the "
            "tag lands a moment before the release object does, and this is the "
            "grace, not a retry-until-green loop -- it gives up and fails."
        ),
    )
    ap.add_argument("--poll-interval", type=int, default=30)
    args = ap.parse_args(argv)

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

    print(f"repo   : {args.repo}   (tags and releases both read from {API})")
    print(f"floor  : {args.floor}")
    print(f"scope  : {args.tag or 'every version tag at or above the floor'}")
    print(f"auth   : {'token' if token else 'ANONYMOUS (60 req/hour)'}")
    print()

    deadline = time.monotonic() + max(0, args.wait_seconds)
    while True:
        try:
            (missing, covered, skipped, ignored), n_tags, n_rel = run_once(
                args.repo, token, args.floor, args.tag
            )
        except CheckError as exc:
            print(f"CHECK DID NOT RUN: {exc}", file=sys.stderr)
            print("This is not a pass.", file=sys.stderr)
            return 2

        if not missing or time.monotonic() >= deadline:
            break
        left = int(deadline - time.monotonic())
        print(f"  {', '.join(missing)} not published yet; {left}s of grace left")
        time.sleep(min(args.poll_interval, max(1, left)))

    print(f"{n_tags} tags and {n_rel} published releases on the remote.")
    print(f"  covered : {len(covered)}  {' '.join(covered) if covered else '-'}")
    if skipped:
        print(f"  skipped : {len(skipped)} below the {args.floor} floor, NOT checked  "
              f"{' '.join(skipped)}")
    if ignored:
        print(f"  ignored : {len(ignored)} tags that are not vMAJOR.MINOR.PATCH  "
              f"{' '.join(ignored)}")
    print()

    if missing:
        print(f"FAIL: {len(missing)} tag(s) with no published release object.")
        for tag in missing:
            print(f"  {tag}  https://github.com/{args.repo}/releases/new?tag={tag}")
        print()
        print("A tag is not a release. The notes for these versions exist only in")
        print("the release commit body, where nobody watching the repo will see")
        print("them. See docs/releasing.md step 4.")
        return 1

    if not covered:
        # An empty in-scope set is the vacuous pass this repo keeps producing.
        # Say so rather than printing OK over a set of size zero.
        print("FAIL: nothing was in scope, so nothing was checked.")
        print(f"  No version tag at or above {args.floor} exists on {args.repo}.")
        return 1

    print(f"OK: all {len(covered)} version tag(s) at or above {args.floor} "
          f"have a published release object.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
