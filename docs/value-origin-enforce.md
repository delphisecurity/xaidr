# Value origin ENFORCE: what it blocks, what it costs, and what is not yet measured

**Status (A2 M8, V-31 as ruled 2026-10-04).** ENFORCE is wired and ships
**OFF**. The default is `value_origin="record"`, which reports and never moves
an action (C-11). Turn on `value_origin="enforce"` only once
`value_origin_sources` designations exist.
- **The rule.** A tool call whose destination traces to an untrusted source is
  blocked: category `untrusted_destination`, rule
  `ORIGIN_UNTRUSTED_DESTINATION`.
- **The audit rule.** The event also carries `intent.value_origin_untrusted`,
  the spec's V-31 key for the waterfall's `decided`.
- **Monitor mode** gives `flagged` instead of `blocked`.
- **When it runs.** It runs before the circuit breaker, the gates and
  detection (V-18), so the block holds on the fail-open paths too.
- **The breaker.** It is NOT counted by the circuit breaker (Q13). If this
  layer could trip the breaker, an open breaker would disable detection
  generally.
- **The zero-designation warning.** An ENFORCE sensor with no designations
  logs one warning at construction, naming what will be blocked.

## What it costs on benign traffic (Q13, measured on this repo's corpora)

With NO designations, every call whose destination came from a tool result is
blocked, benign or not:

| corpus | input-derived | result-derived |
|---|---|---|
| benign (456-row corpus) | 0/83 | 5/83 |
| benign_prose | 6/97 | 7/97 |
| benign_a2a | 0/64 | 4/64 |
| benign_templates | 0/12 | 0/12 |
| benign_longform | 0/24 | 0/24 (*see the anomaly below: not a clean result*) |

## The 18 named benign blocks, and which designation would prevent each

| row | destination | what would prevent it |
|---|---|---|
| input-derived, benign_prose 002, 004, 034, 041, 045, 058 | `evil.tld/x.sh`, 169.254.169.254 credentials (×2), `metadata.google.internal` token, `x.io/i.sh`, `x.io/i` | **Nothing should.** These are attack URLs that benign prose quotes; the harness builds a call to every URL in the text, and blocking a POST to them is correct. **But the property behind it is a DESIGN GAP:** these destinations come from a PRINCIPAL input that L1 flagged, which V-9 makes untrusted. Designations cover tool reads only, so a benign input that L1 flags (a detection false positive) makes every destination it names block. There is no designation-shaped remedy, ~~only spans, or~~ only fixing the detection false positive. *[Corrected, M8 review: declaring the whole input as a PRINCIPAL span still blocks, because a flagged input carries no principal authority (V-9).]* |
| result-derived, benign_prose 002, 004, 034, 041, 045, 055 (`s3://exfil-bucket`), 058 | the same attack URLs, plus `s3://exfil-bucket` | **Nothing should.** These are attack URLs quoted in prose, so a correct block. |
| result-derived, benign 034 | `https://api.github.com/repos/org/repo` | **Through a NAMED seam:** designate the tool that returned it (e.g. a GitHub API tool, `MatchKind.ANY`). **Through the public seam the harness used: nothing can.** **[RULING 3a, 2026-10-04: false as of the commit carrying this mark — the public seam now takes `scan(text, direction="tool_result", tool=..., arguments=...)`; designate the tool and pass them.]** |
| result-derived, benign 035 | `https://api.example.com/health` | the same: designate the runbook/docs reader that returned it (`MatchKind.ANY`), or a `URL_PREFIX` designation on the docs host. Not through the public seam. |
| result-derived, benign 066 | `s3://our-public-assets/` | the same: designate the reading tool. Not through the public seam. |
| result-derived, benign 067 | `https://api.internal/health` | the same. |
| result-derived, benign 068 | `https://reports.internal/q3.pdf` | the same. |

**DESIGN GAP, plainly: the public `scan(direction="tool_result")` seam carries
no tool identity, so NO designation can ever match a read made through it
(V-26).** Every destination such a read names is blocked under ENFORCE, whatever
the operator configures. The same holds for a read made only through
`protect_tools`: it records `result_blocked=None`, which can never be trusted
(Q10). Designations work through the identified seams: the LangChain and MCP
after-hooks, and `_scan_tool_result`. Closing the gap needs an API decision,
for example `scan(..., tool=, arguments=)`.

## Not measured, or not ruled. Do not read these as clean.

- **False positives of the macOS-resolver widening for leading-zero dotted
  quads and leading-zero embedded IPv4: UNMEASURED.** No real text in the
  24,466-file outside corpus contained them; only the number-above-2**32 shape
  has real data (0 action changes). See PROGRESS.md "Before M8, item 2".
- **A destination in an argument longer than 4,000 characters is never
  examined.** S16 gives it a `walk_bound` finding and wire `unresolved`, which
  never blocks, so **an untrusted URL padded past 4,000 chars evades ENFORCE.**
  It is pinned as a strict xfail
  (`test_a_padded_untrusted_url_still_blocks_under_enforce`) pending the
  owner's ruling.
- **The same family: more than 64 argument leaves, or nesting deeper than 6**
  (M8 silent-failure review). Each is a `walk_bound` and `unresolved`, so an
  untrusted destination among 71 arguments evades ENFORCE. It is pinned as a
  strict xfail
  (`test_an_untrusted_destination_among_many_arguments_still_blocks`). One
  ruling on bound hits under ENFORCE should cover every bound.
- **benign_longform's block rate is not measured.** Its 24 calls were each the
  whole document passed as one over-length argument. See the evasion above.

## The benign_longform anomaly, explained (owner condition 3)

~~**Recording was not failing.**~~ *[RETRACTED: the M8 milestone review showed
recording SILENTLY drops every destination more than 65,536 chars into one tool
result (V-15's result-leaf cap). A call to it reads `unresolved`, and ENFORCE
allows it. Every benign_longform document is longer than 64 KiB, so each was only
partly recorded. This is the owner's stop condition. It is pinned as a strict
xfail, `test_a_destination_past_64k_in_one_tool_result_is_still_recorded`.]*
Each document's result recorded up to 67 destinations, from its first 64 KiB. The harness's `calls_for` built exactly ONE call per document:
`run_command` with the whole document as its argument, because it builds calls
only from `scheme://` URLs and mailboxes, and these documents name destinations
as bare hosts. That argument exceeds the core's 4,000-char argument-leaf bound,
which gives `walk_bound` and `unresolved`. So the 0/24 is an artefact, not a
clean rate, and the bound behind it is the ENFORCE evasion above.

## Rule names: one point needs the owner

The owner ruled category `untrusted_destination` and rules
`ORIGIN_UNTRUSTED_DESTINATION` "and the keyed variant, as designed". The
settled spec's V-31 (delphi-sentinel `docs/value-origin-architecture.md`) names
rule `intent.value_origin_untrusted` and category `value_origin_unauthorized`,
and defines **no keyed variant**. This build:
- uses the owner's category and rule;
- carries the spec's audit rule beside them, because the waterfall's `decided`
  keys on it;
- implements no ~~keyed variant, since nothing defines it~~ separately named keyed variant. *[M8 review: C-19 says the waterfall keys `decided` "on the rule id because that is the AUDIT EVIDENCE", so "the keyed variant, as designed" most likely MEANS `intent.value_origin_untrusted`, which this build already emits. The spec's category `value_origin_unauthorized` is NOT carried. Owner to confirm.]* **[RULING 4, 2026-10-04: wrong — the keyed variant is `ORIGIN_UNTRUSTED_DESTINATION_KEYED`, which nothing emits; `intent.value_origin_untrusted` is the spec's C-19 audit id, not the keyed variant.]**

All three names are constants in `xaidr/sensor.py`.

## Owner review gaps recorded at the M8 STOP (not fixed)

- **benign_a2a's 4 result-derived blocks have no designation line.** They were
  measured, not analysed.
- **The §4 acceptance cases were SUBSTITUTED, and not labelled at the time.**
  §4 defines them on `drivers/langchain_poisoned_read.py`, which does not
  exist. M8's driver reads through the private `_scan_tool_result`, never
  checks for a `[BLOCKED]` ToolMessage, and designates `MatchKind.ANY` where
  §4 says EXACT.
- **The zero-designation warning says "will be blocked".** Under the default
  `enforcement_mode="monitor"` these calls are FLAGGED, not blocked. It also
  omits destinations from a flagged principal input, which block whatever the
  designations are.


## Every bound blocks under ENFORCE (owner RULING 1+2, 2026-10-04)

The owner: *"Every bound in this system fails open and silently ... An attacker needs padding, not skill."*
The cap numbers are unchanged. What exceeding one MEANS is new: each bound is a visible wire value, and under ENFORCE it blocks.

| bound | before | now |
|---|---|---|
| argument leaf over 4,000 chars, more than 64 argument leaves, argument nesting deeper than 6 | `walk_bound` finding, wire `unresolved`, allowed | wire **`argument_bound`** (verdict `unresolved`, row `ran_evidence`), blocks |
| tool-result leaf over 65,536 chars, more than 64 result leaves, result nesting deeper than 6 | the cut part SILENTLY unrecorded; a destination in it read `unresolved`, allowed | the ledger is marked; a later miss reads **`result_truncated`** (verdict `not_evaluated`, row `not_recorded`), blocks |
| principal input over 65,536 chars | `input_truncated`, allowed | `input_truncated`, **blocks** |
| ledger full (LEDGER_MAX_ENTRIES) | `ledger_saturated`, allowed | `ledger_saturated`, **blocks** |

**Why two new states, not one.** `argument_bound` is a fact about THIS CALL: some of its arguments were never read, so it holds with no lookup at all. `result_truncated` is a fact about the LEDGER: an earlier result was cut, and it matters only when this call's destination misses. A call can be both. One state would have to say "one of two things happened", and an operator could not tell which.

**Extended past the four bounds the owner named, for the owner to confirm or reverse.** `input_truncated` and `ledger_saturated` already had visible states but still ALLOWED. Both are padding routes:
- A single result with enough distinct URLs saturates the ledger, and the poison in it is dropped (`test_a_saturating_result_does_not_launder_its_poison`).
- A declared-span input padded past the cap hides whatever follows.

This reverses the M6 pin "input_truncated never blocks". The test that held it is renamed at its site.

**An untrusted finding still outranks every bound.** A positive finding is not downgraded to a blind spot.

**Cost.** False positives on legitimate large results are accepted (the owner).
- The 456-row, adversarial and conformance passes of `q13_block_rate.py` are byte-identical before and after (PROGRESS.md, RULING 1+2). None of their calls hits a bound.
- **benign_a2a and benign_longform were NOT re-measured in this round.** The method that produced 4/64 and 0/24 above is not in `q13_block_rate.py` or the report scripts.
- The prediction for benign_longform is that most or all of its 24 calls now block, because every document is over 64 KiB and each `run_command` argument is over 4,000 chars. **That is a prediction, not a measurement.** The 0/24 in the table above is stale as of this commit.

## Known limitation: a flagged benign input poisons its own destinations (owner RULING 3b)

V-9: when the input scan flags the principal's input, every destination candidate in that input is recorded `untrusted_source`.
- A benign input that the scanner misreads (prose that quotes attack URLs, a security write-up, an incident report) therefore marks the user's OWN destinations untrusted, and ENFORCE blocks them.
- **No designation can prevent this.** Designations cover tool results, never the principal's input.
- The six input-derived benign_prose rows above are this shape.

This is not papered over. It is recorded here as a known limitation, and it is an argument for **ENFORCE staying off by default**: the scanner's false-positive rate on inputs becomes value origin's block rate on the user's own destinations.

## The public tool_result seam has an identity (owner RULING 3a)

`sensor.scan(text, direction="tool_result", tool="directory_lookup", arguments={"query": "Jordan"})`
- Both keywords are keyword-only. With `tool=`, the read can match a `value_origin_sources` designation, and the scan's own pre-mode verdict decides whether it is clean, exactly as the named seams do.
- Without `tool=`, the read is nameless and untrusted (V-26, unchanged).
- On any other direction the keywords are ignored, and one warning says so.

## Rule names (owner RULING 4)

- Category `untrusted_destination`; rule `ORIGIN_UNTRUSTED_DESTINATION`. A bound block carries the same category and rule; the wire value says which bound.
- **`ORIGIN_UNTRUSTED_DESTINATION_KEYED` is not emitted anywhere.** It is in no tree I searched: this repo, delphi-sentinel's docs, and delphi-sentinel's full history (`git log --all -S ORIGIN_UNTRUSTED_DESTINATION` finds nothing). No document I can read defines its trigger, so none was invented.
- `intent.value_origin_untrusted` is still emitted. It is the spec's C-19 audit id (the waterfall keys `decided` on it), NOT the keyed variant. Dropping it is the owner's call.
- `value_origin_unauthorized` is not carried.
