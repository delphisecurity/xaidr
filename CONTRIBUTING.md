# Contributing to xaidr

Thanks for your interest in contributing! Please read this before opening a pull
request.

## Reporting a security vulnerability

Not here. `xaidr` is a security product, so a bypass filed in the public tracker
is a bypass published. Use [GitHub private vulnerability
reporting](https://github.com/delphisecurity/xaidr/security/advisories/new), or
email support@delphisecurity.ai.

[SECURITY.md](SECURITY.md) draws the line that matters: a **bypass** is a
vulnerability and goes private, a **missed detection** is a known measured gap
and belongs in the open tracker where it can be discussed. If you are unsure
which one you have, send it privately and we will move it.

## Where to start

The most useful contribution to a detection tool is usually not a new rule. It
is a case.

- **A command or statement we miss.** Open a
  [missed detection](https://github.com/delphisecurity/xaidr/issues/new/choose)
  issue. The form asks for a benign lookalike, and that field is the point of it:
  see [The benign gate](#the-benign-gate-and-the-time-it-caught-us) below.
- **A false positive.** Ordinary work that we block or score. These are treated
  as first-class bugs, because the failure mode that gets a security tool
  switched off is the tool blocking something that was fine.
- **A corpus entry.** `tests/fixtures/shell_corpus.json` holds 281 attacks, 74
  benign commands and 66 benign prose passages. Adding to the benign side is as
  valuable as adding to the attack side and is a smaller change.
- **Documentation.** If a number in `README.md` disagrees with what the code
  does, the number is the bug.

Python 3.10, 3.11 and 3.12 are supported. `pip install ".[http,trace,dev]"` then
`python -m pytest -q`.

## Every detection change is measured

A rule that misses and a rule that over-blocks look identical in a diff. They
look completely different in the corpus report. So detection changes are
measured, not eyeballed:

```
python scripts/corpus_report.py
```

Run it before your change and again after, and put both tables in the pull
request. The header names the package and version that produced each table, so a
reviewer can confirm the two runs measured the same tree.

This is not a convention you are trusted to follow. The `corpus` job in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the same script on
every pull request and prints the table into the log, and it exits non-zero if a
benign gate is violated. The regression floors live in the test suite
(`ATTACK_BASELINE_*` in `tests/test_benign_prose.py`, the per-class floors in
`tests/test_shell_classes_stage3.py`), and that is deliberate: reading the
numbers is a human job, holding the line is pytest's.

If your change moves a floor, move it **with the measurement** and say so in the
commit. A floor lowered to match a regression is a regression with paperwork.

## Where coverage is weak

Current shipped behaviour, measured on the committed corpus: 267 of 281 attacks
are classified (95%), 160 are blocked with no configuration (57%). Those are two
different capabilities and the gap between them is deliberate. Most of the
ruleset names an impact class and leaves the decision to a policy you write.

If you are looking for somewhere your work will matter:

| family | blocked | why it is open |
|---|---|---|
| `discovery` | 2 of 11 | The genuinely weakest. Only 4 of 11 even classify. Enumeration overlaps almost entirely with ordinary operational inspection. |
| `escalate` | 11 of 37 | Classifies fully, blocks under a third. |
| `execute` | 24 of 59 | Same shape: the class is known, the enforcement is not. |
| `infra_destruction` | 0 of 8 | **By design, not a gap.** Destroying managed infrastructure is indistinguishable from a legitimate teardown at the command level, so every rule in the family is classify-only. Do not "fix" this by adding a `detect` block. Improving it means better classification, or a worked policy example. |

Note what is *not* on that list. `persist` blocks 17 of 31, above the median,
and `evade` blocks 29 of 30. Please do not open work against those on the
assumption that they are weak.

## The benign gate, and the time it caught us

Every pull request is gated on 0 of 74 benign commands scoring, and on no
undocumented benign prose passage blocking. That gate exists because of this,
and it is worth reading before you write a pattern.

Rules added in one release made *prose about* dangerous commands score exactly
like the commands themselves. An incident report, a runbook, a policy document
or a detection-rule doc that merely quoted a command blocked: **30 of 66
passages on the content path, 35 of 66 as a tool argument.** That text is what
security teams hand their agents all day.

The obvious fix was to teach the scanner to recognise a documentary frame,
"Runbook:" and friends, and dampen on it. That fix was **deliberately rejected**,
because it is a bypass: an attacker prefixes `Runbook: ` to a live command and
is dampened by the same code.

What shipped instead is structural, and all three conditions are required:

1. the dangerous content sits inside a markdown code span, so it is quoted
   rather than issued;
2. a documentary frame cue appears in the prose outside that span;
3. the **prose residue**, the input with every code span removed, carries no
   dangerous signal of its own.

Condition 3 is the anti-bypass half. A bare prefixed attack has no code span, so
1 fails. A mixed payload (`Runbook: \`ls -la\`, then rm -rf /`) has a live
command in the residue, so 3 fails. Both stay blocked. The frame cue is only a
corroborator and is never the anchor. Result: 30 blocked became 1, 35 became 0,
and the movement was block to flag rather than block to allow, so the passages
still surface.

The lesson generalises. **When a rule fires on something benign, the fix is
almost never a keyword that recognises the benign case**, because the attacker
can write that keyword too. It is a structural property the attacker cannot
forge. That is also why the missed-detection form asks you for a benign
lookalike: the lookalike is what tells us whether a proposed rule keys on
behaviour or on a spelling.

The one passage that still blocks, `bp-055`, is documented by ID with its cause
in `tests/test_benign_prose.py` rather than suppressed, so that a second one
shows up as a new entry instead of disappearing into a percentage.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Reports go
to support@delphisecurity.ai.

## License of contributions

This project is licensed under the [Apache License, Version 2.0](LICENSE).
By submitting a contribution, you agree that your contribution is provided under
the same Apache 2.0 license.

## Developer Certificate of Origin (DCO)

Every commit must be signed off under the
[Developer Certificate of Origin](./DCO), Version 1.1. The sign-off certifies
that you wrote the change (or otherwise have the right to submit it under the
project's open source license) as set out in the DCO.

Sign off your commits with:

```
git commit -s
```

The `-s` flag appends a trailer to the commit message in the form:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email in the trailer must be real and must match the commit
author's name and email. Anonymous or pseudonymous sign-offs are not accepted.

If you forgot to sign off, amend the most recent commit with:

```
git commit --amend -s
```

For a branch with several commits, rebase and sign each one:

```
git rebase --signoff <base-branch>
```

## Pull requests

A CI check verifies that every commit in a pull request carries a valid
`Signed-off-by` trailer. Pull requests with any unsigned commit will fail that
check and cannot be merged until every commit is signed off.
