# Security Policy

`xaidr` is a security product, so it has two kinds of security issue and they go
to two different places. Please read the split before you file, because sending a
detection gap through the private channel delays a fix that could have been
discussed in the open, and sending a real vulnerability to the issue tracker
publishes it before there is anything to upgrade to.

## Reporting a vulnerability

**Preferred channel: [GitHub private vulnerability
reporting](https://github.com/delphisecurity/xaidr/security/advisories/new).**
It keeps the report, the discussion, the fix and the CVE in one place, and it
never exposes the details until an advisory is published.

If you cannot use GitHub, email **support@delphisecurity.ai**. Please put
`xaidr` in the subject line.

Do not open a public issue for a vulnerability.

### What we would like in the report

None of this is mandatory. A report with only the first item is still worth
sending.

- what an attacker gets, in one sentence
- the smallest input that shows it, ideally as a `Sensor` call we can paste into
  a Python prompt
- the version (`python -c "import xaidr; print(xaidr.__version__)"`) and the
  Python version
- whether it needs a non-default configuration, and which one

### What to expect

- an acknowledgement within 3 working days
- an assessment, with our reading of the severity and our reasoning, within 10
  working days
- if we agree it is a vulnerability, a fix and an advisory, and credit to you in
  it unless you would rather stay anonymous

If you have not heard anything in 10 working days, please chase us. A silent
report is a failure on our end, not a signal that we disagree.

We ask that you give us 90 days before publishing. We are not going to argue
about that deadline if we have gone quiet on you.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x | yes |
| < 1.1 | no, please upgrade |

Fixes land on the latest minor release. There is no long-term support branch.
Supported Python versions are whatever `pyproject.toml` claims (currently 3.10,
3.11 and 3.12); CI derives its matrix from that file rather than hardcoding it,
so the two cannot quietly disagree.

## What counts as a vulnerability

**In scope.** Anything that breaks the sensor as a control, or makes it unsafe
to embed:

- a **bypass**: input that a shipped rule is meant to catch, dressed up so it is
  not caught. Encoding tricks, normalization gaps, parser confusion, a payload
  smuggled through a structure the scanner does not descend into.
- a **crash or a hang** in the host process. The sensor is embedded in someone
  else's agent and must never take it down. Catastrophic backtracking in a
  pattern (ReDoS) belongs here.
- **policy enforcement that does not enforce**: a rule that loads and appears to
  bind, but silently does nothing, or a verdict that is downgraded when it
  should be halting.
- **leakage by the sensor itself**: secrets, credentials or customer input
  written into logs, telemetry or exception text.
- anything that lets an untrusted **input** change the sensor's configuration,
  its thresholds, or its rule set.

**Not in scope, and this is the important half.**

- **A missed detection is not a vulnerability.** The shipped ruleset blocks 160
  of 281 attacks in the committed corpus, 57%, and that number is published in
  [Coverage and limitations](README.md#coverage-and-limitations) precisely so
  that nobody has to discover it by surprise. A command we do not catch is a
  known, measured, open gap. Please file it as a normal issue so it can be
  discussed and measured in public.
- **A classify-only rule that does not block is working as designed.** Large
  parts of the ruleset deliberately name an impact class and leave the decision
  to a policy you write. `infra_destruction` blocks 0 of 8 corpus cases on
  purpose, because destroying managed infrastructure is indistinguishable from a
  legitimate teardown at the command level. See the same README section.
- **Running with detection and no policy.** If you have not bound a
  `require_approval` rule to the classify-only families, they are observed and
  allowed. That is documented behaviour, not a flaw.
- Findings from an automated scanner with no demonstrated impact.
- Vulnerabilities in your own agent, model or tools, which the sensor observes
  but does not own.

If you are unsure which side a finding falls on, use the private channel. We
would much rather triage a detection gap out of the advisory queue than read
about a bypass on a mailing list.

## Where the boundary actually sits

Two things about the design are worth knowing before you report, because they
turn what looks like a bug into expected behaviour.

**The sensor fails open, deliberately, and says so.** On an unexpected internal
fault a scan returns `allowed` rather than raising into the host, because a
security sensor that crashes the agent it protects has done more damage than the
attack. It is not a silent allow: the event is emitted with a distinct,
alertable marker (`SCAN_FAILED_OPEN`) and a WARN log. A fault you can trigger
deliberately is very much in scope. The fail-open response to it is not.

**Enforcement is narrower than classification, and the gap is the product.** 95%
of the corpus is assigned a class and tier; 57% is blocked with no
configuration. The families that block well under half their cases are named in
the README rather than hidden: `escalate` blocks 11 of 37 and `execute` blocks
24 of 59. The genuinely weakest are `infra_destruction` at 0 of 8 and `discovery`
at 2 of 11. Those numbers are reproduced on every pull request by the `corpus`
job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml), so they are
current rather than aspirational.

## A note on false positives

A false positive is not a vulnerability, but it is close to one in effect: the
failure mode that gets a security tool switched off is the tool blocking work
that was fine. We treat it as a first-class bug and CI gates on it, at 0 of 74
benign commands scoring and at most 1 of 89 benign prose passages blocking, with
that one documented by ID.

It is also where the temptation to fix things the wrong way is strongest, and
there is a worked example in the history. In `449dff8`, prose that merely quoted
a dangerous command was blocking: an incident report or a runbook scored exactly
like the command it described, 30 of 66 passages on the content path. The
obvious fix was to teach the scanner to recognise a documentary frame, "Runbook:"
and friends, and dampen on it. That fix was deliberately rejected, because it is
a bypass: an attacker prefixes `Runbook: ` to a live command and is dampened by
the same code. What shipped instead is structural. The dangerous content has to
sit inside a markdown code span, and the prose with every code span removed has
to carry no dangerous signal of its own. The frame cue is only a corroborator,
never the anchor.

So if you report a false positive, the useful thing is not a pattern to suppress.
It is the benign text itself, which becomes a corpus entry and stays asserted
forever.

## Hardening this repository

Contributions that reduce the attack surface of the project rather than the
product are welcome as ordinary pull requests: supply-chain hardening, pinning,
workflow permissions, reproducible builds. CI already runs on `pull_request`
rather than `pull_request_target` for exactly this reason, and needs no secrets.
