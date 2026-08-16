<!--
Thanks for contributing to xaidr. Please keep the headings below; a reviewer
should be able to answer "is this safe to merge" without checking the branch
out. Delete the HTML comments as you go.

New here? CONTRIBUTING.md covers the licence and the sign-off. SECURITY.md
covers what belongs in a private report instead of a pull request. If this
change fixes a vulnerability, stop and read SECURITY.md first.
-->

## What this changes

<!-- One or two sentences. What is different after this merges? -->

## Why

<!-- What was wrong, or what was missing. Link an issue if there is one. -->

## Sign-off

Every commit in this pull request carries a `Signed-off-by` trailer under the
[Developer Certificate of Origin](https://github.com/delphisecurity/xaidr/blob/main/DCO),
and the name and email in it are real
and match the commit author.

- [ ] Every commit is signed off (`git commit -s`, or `git rebase --signoff <base>`)

<!--
A CI check verifies this on every commit, so an unsigned commit will fail the
build rather than reach a reviewer. Checking the box is how you confirm the
name and email are genuinely yours, which CI cannot tell.
-->

## Corpus impact

<!--
Detection and rule changes are MEASURED, never eyeballed in a diff. A rule that
misses and a rule that over-blocks look identical in a patch and completely
different in this table.

Run it before and after your change, from the repository root:

    python scripts/corpus_report.py

Paste both headers and both tables below. The header names the package and
version that produced each table, so a reviewer can see the two runs measured
the same tree.
-->

- [ ] This change cannot affect detection (docs, CI, packaging, tests only), so there is no table
- [ ] This change can affect detection, and both tables are below

<details>
<summary>Before</summary>

```
paste the output of `python scripts/corpus_report.py` on the base commit
```

</details>

<details>
<summary>After</summary>

```
paste the output of `python scripts/corpus_report.py` with this change applied
```

</details>

### What moved, and why

<!--
Walk the reviewer through the deltas. Numbers that went up need a sentence as
much as numbers that went down.

  * which classes changed, and by how much
  * anything that got WORSE, said plainly. A trade is fine, a hidden trade is not
  * if a test floor moved (ATTACK_BASELINE_*, CREDENTIAL_FLOOR, the per-class
    floors), say which, to what, and why the measurement justifies it rather
    than the other way around
-->

## Benign gates

The report enforces these and exits non-zero if either is violated. Confirm what
your "after" run said:

- [ ] benign commands: 0 of 74 scored, 0 of 74 blocked
- [ ] benign prose: no UNDOCUMENTED passage blocks

<!--
If you had to add an entry to KNOWN_BLOCKING_PROSE in
tests/test_benign_prose.py, that is a NEW accepted false positive and needs its
own paragraph here explaining why it is accepted rather than fixed. Do not let
it pass as a routine line in the diff.

If your change fixes a false positive: the deliverable is the benign text added
to tests/fixtures/shell_corpus.json, not a suppressed pattern. The text is what
stays asserted.
-->

## Checks

- [ ] `python -m pytest -q` passes locally
- [ ] New behaviour has a test that fails without the change
- [ ] No new required runtime dependency (`xaidr` installs with none, and that is a promise)
- [ ] Documentation updated if this changes what a user sees, including any number quoted in README.md

## Anything else a reviewer should know

<!-- Known gaps, follow-up work, decisions you are unsure about. -->
