# Cutting a release

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

This is the maintainer procedure for cutting a release. It is written down
because the parts of it that were only ever in a working session are the parts
that went wrong.

On 2026-09-09 this repository had **fifteen tags and zero release objects**. The
notes for every one of those releases — including a webhook credential leak that
required anyone on 1.13.0 or 1.14.0 to rotate a secret, and a CrewAI boundary
that 1.6.1 reported as PATCHED while a destructive tool call executed anyway —
existed only inside a release commit body. `git log` had them. Nobody watching
the repository was told any of it. Every CI run was green the entire time,
because nothing in CI could see server-side state.

**A tag is not a release.** The release object is the artifact a consumer reads;
creating it is step 5, not a follow-up.

## The five steps

### 1. Reconcile the notes against the range

Write the notes in the release commit body. Then, before anything else, print
the range they claim to describe:

```
git log --oneline <previous-tag>..HEAD
```

Tick every line as **described** or **deliberately silent**. Not "skimmed" —
ticked, one line at a time, in the pull request.

This is the step that failed at 1.15.0. The notes were drafted, PR #5 merged
after they were drafted, and the release shipped describing the resource-bound
detector only. Three of the seven commits in the range — the `SensorExtension`
seam, the monitor-mode field-loss fix, and the per-site fail-open sabotage —
went out undescribed, and one of them changes what a monitor-mode sensor returns
to its caller. **Notes written before the last merge are notes about a different
release.**

Then check every commit SHA the notes cite:

```
for sha in $(grep -oE '\b[0-9a-f]{7,40}\b' notes.md); do
  git merge-base --is-ancestor "$sha" HEAD || echo "NOT AN ANCESTOR: $sha"
done
```

1.15.0's notes cite `a64207e` and `64ec128` for the two false-positive fixes.
Both live on an unmerged branch and neither is an ancestor of the tag; the
commits that shipped are `909b8dd` and `c31d10f`. A reader who tries to look
them up gets nothing.

### 2. Tag locally. Do not push yet

```
git tag -a "v$VERSION" -F notes.md
```

The tag is created before the verification below because the verification builds
*from the tag*, and it is not pushed until the verification passes. A pushed tag
is public and a release you have not verified should not be.

### 3. Build from a clean clone of the tag, and verify from the artifact

Not from the working tree, and not from an editable install. The tree is what
you have been editing; the artifact is what a consumer gets, and the two differ
in ways that only show up here — `docs/` ships in neither artifact, the wheel is
`packages = ["xaidr"]` and the sdist is `["xaidr", "README.md", "pyproject.toml"]`.

```
git clone --branch "v$VERSION" --single-branch . /tmp/rel && cd /tmp/rel
python -m build
python -m venv /tmp/relvenv && /tmp/relvenv/bin/pip install dist/*.whl
```

Then verify **at a neutral cwd, with `xaidr.__file__` asserted inside
site-packages**:

```
cd / && /tmp/relvenv/bin/python -I -c "
import xaidr
assert 'site-packages' in xaidr.__file__, xaidr.__file__
print(xaidr.__version__, xaidr.__file__)
"
```

Both halves are load-bearing and neither is optional:

- **Neutral cwd + `python -I`.** Run from the source tree, Python puts the
  source tree on `sys.path` and imports `./xaidr/` in preference to the
  installed package. Every claim you then make is about the tree you were just
  editing, wearing the version number of the artifact.
- **`xaidr.__file__` in site-packages.** This is the assertion that catches it.
  Printing the version does not: `xaidr.__version__` is the same string in both,
  which is exactly why a version check reads as a verification while performing
  none.

Anything the notes claim about the shipped package — a redaction, a boundary, a
refusal shape — is measured here, in this interpreter, and the output is pasted.

### 4. Prove detection did not move, and name every change that did

The claim to make is **byte-identical, with every intended change named**, and
it is made against the *published* previous wheel, not the previous worktree:

```
pip download "xaidr==$PREVIOUS" --no-deps -d /tmp/prev
```

Scan the corpus under both wheels on all four boundaries — input, output, tool,
A2A — and compare `action`, `score`, `category` and the **ordered rule list**
value for value. One digest over the whole set is the summary; the diff is the
evidence. Then:

- **If nothing moved**, say so with the digest and the row count.
- **If something moved, enumerate it in full.** 1.15.0 moved eleven verdicts and
  listed all eleven with the rule that caused each. 1.14.1 moved twelve and
  listed twelve. That is the standard: a count without the rows is a number a
  reader cannot check.
- **Report residual false positives as a number, never as "clean".** 1.15.0
  ships at 2 of 50 on the discriminator pool and says so, because 2 is what it
  is.
- **Name the pool that could not see the class.** Both of 1.14.1's fixes were
  invisible to the 190-call benign corpus by construction. "0/190" was true and
  meaningless for the entire time the detector was flagging a fifth of realistic
  traffic.

### 5. Push the tag, then create the release object

In that order, minutes apart. The release object is extracted from the commit
body — not retyped, not summarised:

```
git push origin "v$VERSION"

git show -s --format=%b "v$VERSION" \
  | sed '/^\(Co-Authored-By\|Claude-Session\|Signed-off-by\):/d' > /tmp/notes.md

gh release create "v$VERSION" --verify-tag \
  --title "v$VERSION — <one line>" --notes-file /tmp/notes.md
```

Three things about the body:

- **`--notes-file`, always.** Retyping is how a release note drifts from the
  commit it describes.
- **Fence the column-aligned blocks.** Verdict diffs, suite tables and pasted
  interpreter output are aligned with spaces; GitHub-flavoured Markdown strips
  leading indent and collapses runs of spaces, so an unfenced evidence table
  renders as ragged prose. The bodies are the evidence — losing their alignment
  loses the point of them.
- **Security content gets said in the title.** `Security:` plus the affected
  versions, a banner above the body naming the action a reader must take, and a
  GHSA advisory if it warrants one. Five of this project's releases were
  security releases and none of them said so anywhere a consumer would look:
  v1.4.1, v1.6.2, v1.11.0, v1.13.0, v1.14.1.

Finally, paste the proof:

```
gh release view "v$VERSION" --json tagName,isDraft,publishedAt,htmlUrl
```

## U-1 — no figure without a regenerator

**No number ships in a release body, in `README.md`, or in any `docs/` page
unless a committed script regenerates it, and the release body names that
script.**

Not "a script exists somewhere". Not "it was measured". A path in this
repository that a reader can run.

This rule has a measured cost of being absent. Seven distinct hex digests are
cited across six release bodies — v1.9.0, v1.10.0, v1.11.0, v1.12.0, v1.13.0 and
v1.14.0 — as the proof that detection did not move:

```
v1.9.0    25606dd56cbbadb9024310be2ae39921216fe114286b87febca789a52fb1ad02
v1.9.0    bb8e8502                                    (wheel digest, truncated)
v1.10.0   9e2d30012258e6cd38d586be2f6963d3640f51cb3979129714ff29a907a7ec19
v1.10.0   cf1f8a4f                                    (wheel digest, truncated)
v1.11.0   9e2d30012258e6cd38d586be2f6963d3640f51cb3979129714ff29a907a7ec19
v1.11.0   a9503119                                    (wheel digest, truncated)
v1.12.0   d02a18b56e31dd02e44c76eb78b9fd1c0d6cae958e87447fe9aa50ec9c78253b
v1.13.0   d02a18b56e31dd02e44c76eb78b9fd1c0d6cae958e87447fe9aa50ec9c78253b
v1.14.0   36a80b7aa52fbd8430428eeb8c6e3e920dc3923bca176738c6ec62434c213d78
```

**Not one of them has ever appeared in a committed file, on any branch, at any
point in this repository's history.** `git log --all -S<digest> --pickaxe-all`
finds nothing for all seven. No script in `scripts/` computes a corpus verdict
digest at all.

So the strongest evidence these releases offer — the thing the phrase
"BYTE-IDENTICAL" rests on — cannot be reproduced, cannot be disproved, and
cannot be told apart from a number that was typed. That is worse than omitting
it: an unreproducible digest reads as rigour and supplies none, which is the
same failure as a `content_hash` computed from the tool name, or a `/health`
endpoint answering with a hardcoded literal.

The rule is one sentence with one exception, and the exception is stated in
public:

- A figure with a regenerator names it: `python scripts/corpus_report.py`,
  `python scripts/intent_metrics.py`, `python scripts/asi_battery_report.py`,
  `python scripts/heldout_report.py`, `python scripts/benign_toolcall_report.py`.
- A figure whose regenerator would leak a working set of attacks that defeat the
  shipped rules is **withheld with that reason given**, as `heldout/` already
  does. Withheld is honest. Unreproducible-but-quoted is not.
- A figure that could not be measured in this environment is **withdrawn, not
  restated**. 1.15.0 did this correctly with the rules+nano column: the `nano`
  extra was absent, the stale 55/120 was withdrawn rather than repeated, and the
  regeneration command was named.

The debt this creates is a corpus-digest regenerator that does not yet exist.
Until it does, a release body claiming byte-identical detection names the wheels
compared, the pools, the row count and the boundaries — and does **not** publish
a digest nobody can recompute.

## The gate

`scripts/release_objects_gate.py` fails if a version tag exists with no
published release object. `.github/workflows/release-gate.yml` runs it on every
`v*` tag push, on a daily schedule, and on demand.

**It reads GitHub's API for both sides of the comparison** — the tag list and
the release list — and never `git tag`. That is the property worth having.
`ci.yml` proves the tree is self-consistent; it has no view of GitHub, and the
fifteen-tags-zero-releases state was invisible to it for months while it stayed
green. A gate that compared a local tag list against a remote release list would
be measuring the runner: `actions/checkout` fetches no tags by default, so the
tempting shortcut passes vacuously on an empty set.

What counts:

- **A draft does not count.** A draft is what an interrupted release leaves
  behind. It is invisible to non-maintainers and notifies nobody.
- **Tags below `--floor` (default `v1.10.0`) are reported and skipped**, not
  silently dropped — the run prints them, so the output cannot read as full
  coverage. The floor is where this process took effect. A floor is used rather
  than a grandfathered list because an exception list never shrinks; a floor is
  monotone and every future tag is above it.
- **Exit 2 is "could not run", distinct from 0 and 1**, so a rate limit or an
  auth failure can never be mistaken for a pass.

Run it yourself at any time:

```
python scripts/release_objects_gate.py                 # every tag >= floor
python scripts/release_objects_gate.py --floor v1.0.0  # include the pre-policy tags
```

`tests/test_release_objects_gate.py` covers the comparison, and each of its
discriminating cases has been shown to fail against a sabotaged gate — the draft
filter, the vacuous-pass guard, the exit-2 path, version ordering, and the
below-floor report. The network half is not testable in pytest by construction
and is verified by running the script against the live API.

At the time of writing the gate is green at its floor and red at `--floor
v1.0.0`, which names the six pre-policy tags that still have no release object:
v1.5.0, v1.6.0, v1.6.1, v1.7.0, v1.8.0, v1.9.0. Those were left uncut
deliberately — a docs-only republish and an internal evidence correction are
noise as release events — and the floor records that decision rather than hiding
it.
