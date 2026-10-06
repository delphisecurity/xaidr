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
| benign_longform | 0/24 | 0/24 (*see the anomaly below: not a clean result*) **[after RULING 1+2, measured 2026-10-05: 24/24 and 24/24, all `argument_bound`]** |

## The 18 named benign blocks, and which designation would prevent each

| row | destination | what would prevent it |
|---|---|---|
| input-derived, benign_prose 002, 004, 034, 041, 045, 058 | `evil.tld/x.sh`, 169.254.169.254 credentials (×2), `metadata.google.internal` token, `x.io/i.sh`, `x.io/i` | **Nothing should.** These are attack URLs that benign prose quotes; the harness builds a call to every URL in the text, and blocking a POST to them is correct. **But the property behind it is a DESIGN GAP:** these destinations come from a PRINCIPAL input that L1 flagged, which V-9 makes untrusted. Designations cover tool reads only, so a benign input that L1 flags (a detection false positive) makes every destination it names block. There is no designation-shaped remedy, ~~only spans, or~~ only fixing the detection false positive. *[Corrected, M8 review: declaring the whole input as a PRINCIPAL span still blocks, because a flagged input carries no principal authority (V-9).]* |
| result-derived, benign_prose 002, 004, 034, 041, 045, 055 (`s3://exfil-bucket`), 058 | the same attack URLs, plus `s3://exfil-bucket` | **Nothing should.** These are attack URLs quoted in prose, so a correct block. |
| result-derived, benign 034 | `https://api.github.com/repos/org/repo` | **Through a NAMED seam:** designate the tool that returned it (e.g. a GitHub API tool, `MatchKind.ANY`). **Through the public seam the harness used: nothing can.** **[RULING 3a, 2026-10-04: false as of the commit carrying this mark — the public seam now takes `scan(text, direction="tool_result", tool=..., arguments=...)`; designate the tool and pass them.]** |
| result-derived, benign 035 | `https://api.example.com/health` | the same: designate the runbook/docs reader that returned it (`MatchKind.ANY`), or a `URL_PREFIX` designation on the docs host. Not through the public seam. **[RULING 3a, f93e873: false now — the public seam takes `tool=`/`arguments=`, so designating the reading tool works through it too.]** |
| result-derived, benign 066 | `s3://our-public-assets/` | the same: designate the reading tool. Not through the public seam. **[RULING 3a, f93e873: false now — the public seam takes `tool=`/`arguments=`, so designating the reading tool works through it too.]** |
| result-derived, benign 067 | `https://api.internal/health` | the same. **[RULING 3a, f93e873: false now — the public seam takes `tool=`/`arguments=`, so designating the reading tool works through it too.]** |
| result-derived, benign 068 | `https://reports.internal/q3.pdf` | the same. **[RULING 3a, f93e873: false now — the public seam takes `tool=`/`arguments=`, so designating the reading tool works through it too.]** |

**DESIGN GAP, plainly: the public `scan(direction="tool_result")` seam carries
no tool identity, so NO designation can ever match a read made through it
(V-26).** Every destination such a read names is blocked under ENFORCE, whatever
the operator configures. The same holds for a read made only through
`protect_tools`: it records `result_blocked=None`, which can never be trusted
(Q10). Designations work through the identified seams: the LangChain and MCP
after-hooks, and `_scan_tool_result`. Closing the gap needs an API decision,
for example `scan(..., tool=, arguments=)`. **[CLOSED for the public seam by RULING 3a (f93e873): `scan(..., tool=, arguments=)` exists. Still true of a `protect_tools`-only read (`result_blocked=None`, Q10).]**

## Not measured, or not ruled. Do not read these as clean.

- **False positives of the macOS-resolver widening for leading-zero dotted
  quads and leading-zero embedded IPv4: UNMEASURED.** No real text in the
  24,466-file outside corpus contained them; only the number-above-2**32 shape
  has real data (0 action changes). See PROGRESS.md "Before M8, item 2".
- **A destination in an argument longer than 4,000 characters is never
  examined.** S16 gives it a `walk_bound` finding and wire `unresolved`, which
  never blocks, so **an untrusted URL padded past 4,000 chars evades ENFORCE.** **[FIXED, RULING 1+2 (f93e873): `argument_bound`, which blocks; the xfail is now a passing test.]** **[Narrowed 2026-10-05: argument_bound no longer blocks; the padded destination is found by atom extraction and blocks as `untrusted_source`.]**
  It is pinned as a strict xfail
  (`test_a_padded_untrusted_url_still_blocks_under_enforce`) pending the
  owner's ruling.
- **The same family: more than 64 argument leaves, or nesting deeper than 6**
  (M8 silent-failure review). Each is a `walk_bound` and `unresolved`, so an **[Narrowed 2026-10-05: no longer blocks; 7/24 and 8/24 remain, all `untrusted_source` — see the end of this file.]**
  untrusted destination among 71 arguments evades ENFORCE. It is pinned as a **[FIXED, RULING 1+2 (f93e873): `argument_bound`, which blocks; the xfail is now a passing test.]** **[Narrowed 2026-10-05: argument_bound no longer blocks; the padded destination is found by atom extraction and blocks as `untrusted_source`.]**
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
xfail, `test_a_destination_past_64k_in_one_tool_result_is_still_recorded`.]* **[f93e873: renamed `..._reads_result_truncated_and_blocks`; no longer an xfail.]** **[Renamed again 2026-10-05: `..._is_recorded_and_blocks`.]**
Each document's result recorded up to 67 destinations, from its first 64 KiB. The harness's `calls_for` built exactly ONE call per document:
`run_command` with the whole document as its argument, because it builds calls
only from `scheme://` URLs and mailboxes, and these documents name destinations
as bare hosts. That argument exceeds the core's 4,000-char argument-leaf bound,
which gives `walk_bound` and `unresolved`. So the 0/24 is an artefact, not a **[As of f93e873 it is `argument_bound` and blocks: measured 24/24, 2026-10-05.]** **[Narrowed 2026-10-05: no longer blocks; 7/24 and 8/24 remain, all `untrusted_source` — see the end of this file.]**
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
- **The zero-designation warning says "will be blocked".** Under the default **[FIXED in f93e873: the warning says 'blocked' under block mode and 'flagged' under monitor.]**
  `enforcement_mode="monitor"` these calls are FLAGGED, not blocked. It also
  omits destinations from a flagged principal input, which block whatever the
  designations are.


## Every bound blocks under ENFORCE (owner RULING 1+2, 2026-10-04)

**[NARROWED by the owner, 2026-10-05: only `result_unread` still blocks. argument_bound, result_truncated, input_truncated and ledger_saturated are visible states that do not block, and atom extraction finds what a bound used to hide. See "The bounds ruling, narrowed" at the end.]**

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
- The 456-row, adversarial and conformance passes of `q13_block_rate.py` are byte-identical before and after (PROGRESS.md, RULING 1+2). None of their calls hits a bound. **[RETRACTED 2026-10-05: vacuous. `q13_block_rate.py` counted `untrusted_source` only, so it could not see a bound state and was identical by construction. Re-measured with each tree's own `should_block`: see "Re-measured after RULING 1+2" below.]**
- **benign_a2a and benign_longform were NOT re-measured in this round.** The method that produced 4/64 and 0/24 above is not in `q13_block_rate.py` or the report scripts. **[Superseded 2026-10-05: both measured; see below.]**
- The prediction for benign_longform is that most or all of its 24 calls now block, because every document is over 64 KiB and each `run_command` argument is over 4,000 chars. **That is a prediction, not a measurement.** The 0/24 in the table above is stale as of this commit. **[Measured 2026-10-05: 24/24 blocked, every one `argument_bound`.]**

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
- **`tool=` is trusted as given.** Nothing ties it to a real in-flight invocation, so it must come from the host's OWN dispatch, never from model output or content: a `tool=` an attacker can choose lets an untrusted payload claim a designated tool's trust (silent-failure review, 2026-10-05).
- On any other direction the keywords are ignored, and one warning says so.

## Rule names (owner RULING 4)

- Category `untrusted_destination`; rule `ORIGIN_UNTRUSTED_DESTINATION`. A bound block carries the same category and rule; the wire value says which bound. **[Milestone review, 2026-10-05: that was true only of the in-process `ScanResult`. Telemetry had no wire value, so a call with too many arguments was audited as an untrusted destination, `intent.value_origin_untrusted` included. The block event now carries `valueOrigin`. The rule ids still SAY "untrusted" for a bound block: a separate rule id for bound blocks is the owner's naming call.]** **[Answered 2026-10-05: `ORIGIN_UNEXAMINABLE_SOURCE` for the only bound that still blocks.]**
- **`ORIGIN_UNTRUSTED_DESTINATION_KEYED` is not emitted anywhere.** It is in no tree I searched: this repo, delphi-sentinel's docs, and delphi-sentinel's full history (`git log --all -S ORIGIN_UNTRUSTED_DESTINATION` finds nothing). No document I can read defines its trigger, so none was invented. **[Corrected 2026-10-05, owner: it comes from the original value-origin design as the Tier 2 keyed variant and was never built — DESIGNED, NOT IMPLEMENTED (docs/value-origin-rulings.md).]**
- `intent.value_origin_untrusted` is still emitted. It is the spec's C-19 audit id (the waterfall keys `decided` on it), NOT the keyed variant. Dropping it is the owner's call. **[2026-10-05: on a `result_unread` block it IS now dropped. That was MY decision, not the owner's ruling (the owner named only the rule id). Consequence (C-19, PLAUSIBLE): the waterfall marks the intent stage `decided` on that id, so an unexaminable block may show no deciding stage. For the owner.]**
- `value_origin_unauthorized` is not carried.

## Re-measured after RULING 1+2 (2026-10-05)

**[Superseded the same day: these 24/24 were `argument_bound` blocks, which no longer block. Current numbers are under "The bounds ruling, narrowed".]**

`q13_block_rate.py` now counts a block with the tree's own `should_block`. The same instrument was run on 255a4b3 and on f93e873, and it reproduces the one surviving output of the uncommitted script behind the 4/64 and 0/24 figures exactly.

| corpus | input-derived, before → after | result-derived, before → after |
|---|---|---|
| benign (456-row) | 0/83 → 0/83 | 5/83 → 5/83 |
| benign_prose | 6/97 → 6/97 | 7/97 → 7/97 |
| benign_templates | 0/12 → 0/12 | 0/12 → 0/12 |
| benign_a2a | 0/64 → 0/64 | 4/64 → 4/64 |
| **benign_longform** | **0/24 → 24/24** | **0/24 → 24/24** |

**Every one of the 24 benign_longform blocks is `argument_bound`, not `result_truncated`.** The harness puts the whole document (90k–1.4M chars) into ONE argument (`run_command(command=<document>)`). That leaf is over 4,000 chars, so the call is `argument_bound`, which takes precedence over a cut result.

**What this means beyond the corpus: a cost the ruling did not name.** The owner accepted false positives on legitimate large RESULTS. The 4,000-char bound is on ARGUMENTS, and it fires whether or not the long value is destination-shaped. Under ENFORCE, any tool call carrying one string over 4,000 chars now blocks, whatever its destination: an email body, a file write, a long query. Measured here as 24/24 on the one corpus with long arguments.

**A cost the extension to `ledger_saturated` did not state** (milestone review, 2026-10-05, CONFIRMED):

**[Resolved by the owner, 2026-10-05: ledger_saturated no longer blocks. The cap question is answered below.]**
- A benign principal prompt of 17,481 chars saturates the ledger. That is well under the 65,536-char input cap; the prompt's n-grams count toward LEDGER_MAX_ENTRIES.
- From then on, EVERY destination miss in that flow blocks under ENFORCE.
- This extension was made without a ruling, is live in the code, and is listed for the owner to confirm. Reversing it is one line: remove `LEDGER_SATURATED` from `_BOUND_WIRES`.

## Q18 under the bounds ruling: `result_unread` (2026-10-05)

**The Q18 skip itself works.** A result from httpx, requests, urllib3 or aiohttp is not read, so recording never consumes its stream. Until now the skip set no flag: a destination inside such a response was never recorded, and a later call to it read plain `unresolved` and was ALLOWED under ENFORCE. That is the same silent fail-open as the 64 KiB cap.

It was reproduced with REAL unread objects, not stand-ins: an `httpx.Response` on a stream, a `urllib3.HTTPResponse(preload_content=False)` and a `requests.Response`. Each was tested top-level and nested in a dict. In every case the ledger recorded nothing, the call read `unresolved` and was allowed, and nothing was consumed.

**The manifest half of Q18 was never built.** Q18 said to "report them `not_recorded` in the manifest". `ProtectionManifest` (`xaidr/autopatch/manifest.py`) has no value-origin field, and it is returned once by `protect()`, so it cannot carry a per-read state. The visible state is therefore a wire value.

**Now:**
- The skip stays, still unread.
- The core marks the ledger, and a later miss reads **`result_unread`** (verdict `not_evaluated`, row `not_recorded`). It blocks under ENFORCE.
- The sensor's own early return, which never reached the core, is removed. The core's normaliser is the single place that refuses to read.
- An untrusted finding outranks it. Precedence: argument_bound, result_truncated, result_unread, input_truncated, ledger_saturated. **[Corrected 2026-10-05 (milestone review): that order let a non-blocking state hide result_unread. Now: result_unread, argument_bound, ledger_saturated, result_truncated, input_truncated.]**

**Cost:** under ENFORCE, a tool that returns a raw response object makes every later destination miss in that flow block. The fix on the host side is to return the read body (`response.text`), which value origin then reads normally.

## The bounds ruling, narrowed (owner, 2026-10-05)

> "The goal was never that: it was **don't lose the destination**. Blocking is the fallback for a value that genuinely cannot be examined, not the answer to a cost control."

| state | blocks under ENFORCE? | what happens past the bound |
|---|---|---|
| `argument_bound` | **no** (visible) | the parts the walk skipped (the whole over-length leaf, leaves past the 64th, containers deeper than 6) are searched for destination ATOMS, and each atom is evaluated |
| `result_truncated` | **no** (visible) | the same parts of a result are searched for atoms, and each is RECORDED with the result's origin |
| `input_truncated` | **no** (visible) | the sensor no longer cuts the input; the core records atoms from ALL of it and key n-grams from the first 64 KiB |
| `ledger_saturated` | **no** (visible, loud warning) | unchanged: the cap is the question (below) |
| `result_unread` (Q18) | **yes** | a stream cannot be read without consuming it. Category `unexaminable_source`, rule `ORIGIN_UNEXAMINABLE_SOURCE`, never `ORIGIN_UNTRUSTED_DESTINATION` / `intent.value_origin_untrusted` |

"Atoms" are C-7's prose pass (`prose_candidates`) over the WHOLE string, with no leaf, length or depth bound; the walk is cycle-safe. Only the expensive whole-value examination stays bounded. An over-length leaf is handed on whole, so a destination straddling the 64 KiB cut is found (sabotage SA3: handing on only the tail loses it).

**The rule id, and a category the ruling did not name.** The owner ruled a separate rule id for a block on a source that could not be examined. The category `untrusted_destination` would be the same false statement, so it changed too, to `unexaminable_source`. **For the owner to confirm.**

### What it costs (measured, not assumed)
Value origin's own cost, called directly on the core so the scanner's time is excluded. Before is 77d9b4a, after is this commit:
```
BEFORE (77d9b4a)
xaidr from: ./xaidr
the 5 MB case (core value-origin cost only, best of 3):
  record_principal_input  5 MB of 'A' (test_truncation_bypass shape)      241.3 ms
  record_tool_result      5 MB of 'A' (test_truncation_bypass shape)        3.0 ms
  evaluate_call(arg)      5 MB of 'A' (test_truncation_bypass shape)        0.0 ms
  record_principal_input  5 MB of real prose                             1571.7 ms
  record_tool_result      5 MB of real prose                                7.2 ms
  evaluate_call(arg)      5 MB of real prose                                0.0 ms
  END TO END sensor.scan(5 MB 'A', input): value_origin=off 1013 ms, record 1026 ms, delta +13 ms
benign_longform, 24 docs, 10,100,008 chars (core value-origin cost, summed):
  record_principal_input           total     5877 ms    244.9 ms/doc   largest doc 439 ms
  record_tool_result               total      230 ms      9.6 ms/doc   largest doc 7 ms
  evaluate_call(run_command=doc)   total        0 ms      0.0 ms/doc   largest doc 0 ms

AFTER
xaidr from: ./xaidr
the 5 MB case (core value-origin cost only, best of 3):
  record_principal_input  5 MB of 'A' (test_truncation_bypass shape)      219.8 ms
  record_tool_result      5 MB of 'A' (test_truncation_bypass shape)      222.8 ms
  evaluate_call(arg)      5 MB of 'A' (test_truncation_bypass shape)      217.7 ms
  record_principal_input  5 MB of real prose                              565.6 ms
  record_tool_result      5 MB of real prose                              554.9 ms
  evaluate_call(arg)      5 MB of real prose                              550.1 ms
  END TO END sensor.scan(5 MB 'A', input): value_origin=off 1019 ms, record 1234 ms, delta +216 ms
benign_longform, 24 docs, 10,100,008 chars (core value-origin cost, summed):
  record_principal_input           total     2244 ms     93.5 ms/doc   largest doc 172 ms
  record_tool_result               total     1685 ms     70.2 ms/doc   largest doc 162 ms
  evaluate_call(run_command=doc)   total     1486 ms     61.9 ms/doc   largest doc 158 ms
```
- **Atoms cost about 110 ns per char of prose (about 45 on non-prose), linear in the value's size, with no bound.** **[Corrected 2026-10-05 (milestone review): ADDRESS-DENSE text costs ~1.45–1.70 µs/char — 7–8.5 s per 5 MB on EACH path, and an attacker controls it. See "What it costs, corrected" below.]**
- The 5 MB case through the sensor gains **+216 ms** per input scan on a ~1 s scan. **[Corrected: that row used 5 MB of 'A', not test_truncation_bypass's own input; on its input the gain is +510 ms (1.37 → 1.88 s).]**
- 5 MB of real prose costs **about 0.55 s on each path** (input, result, argument).
- **benign_longform:** 94 ms/doc on input, 70 on result, 62 on argument; the 1.4 MB doc costs about 160–170 ms per path.
- `test_truncation_bypass` still passes.
- Whether this counts as "cheap" is the owner's call. These are the numbers.

### Block rate after the narrowing: benign_longform is NOT back near 0
| corpus | input-derived | result-derived |
|---|---|---|
| benign / benign_prose / benign_templates / benign_a2a | unchanged: 0/83, 6/97, 0/12, 0/64 | unchanged: 5/83, 7/97, 0/12, 4/64 |
| **benign_longform** | **7/24** (was 24/24, and 0/24 before RULING 1+2) | **8/24** (likewise) |

**None of these is a bound block. All are `untrusted_source`.** The cause is measured per document (the input scan's own verdict, and whether the document contains a URL): `  (input scan, has atoms): {('allowed', False): 3, ('flagged', False): 13, ('flagged', True): 7, ('allowed', True): 1}`.
- **Input-derived:** the 7 blocks are exactly the 7 documents that the input scan FLAGS (mostly `oversized_input`, which fires at ~150K chars) AND that contain URLs. V-9 makes every candidate of a flagged input untrusted, and atom extraction now finds those URLs in the call. This is RULING 3b's flagged-benign-input limitation. The 64 KiB cut had been hiding it. **[Corrected 2026-10-05 (milestone review): wrong twice. Only 3 of the 7 are `oversized_input` (thread_dump); 4 are kubectl_dump, flagged `pii_detected` / `data_exfiltration`. And the URLs were recorded before too (thread_dump's atoms sit inside the first 64 KiB): what uncovered these blocks is atom extraction on the over-4,000-char ARGUMENT, which used to be unexamined.]**
- **Result-derived:** the 8 blocks are the 8 documents with URLs. Read as a tool result with no designations, every URL in one is untrusted, and the harness passes the whole document back as one argument.

**An asymmetry for the owner.** C-8 makes an argument leaf a destination only if its WHOLE value is one, so a 3,999-char email body quoting an untrusted URL does not block. Over 4,000 chars, the same body's URL is found as an atom and does block. Long arguments are now STRICTER than short ones. The options:
- (a) accept it;
- (b) past the bound, take only atoms that make up the whole value. The padding threat, `https://evil/?q=aaaa…`, is that shape;
- (c) extract atoms from short leaves too, which is stricter everywhere.

### What the ledger cap should be (asked by the owner)
- **Measured:** a 17,481-char prompt yields 13,134 key n-grams, and a full 64 KiB prompt yields 49,262. All of them share the 10,000-entry cap with destinations. An entry costs ~117 bytes.
- **Recommendation: give the principal's key n-grams their OWN budget,** sized to the 64 KiB n-gram window (65,536 entries, ≤ ~7.7 MB per flow at 117 B), and keep destinations at their own 10,000. Then n-grams can never starve destination recording. A single shared cap would need ≥ ~60,000 to hold one full input plus its destinations.
- **Known gap, either way:** an attacker-controlled result with more distinct URLs than the cap still saturates the ledger, and the poison in it is dropped. Saturation no longer blocks, so that call is allowed. This is pinned as a strict xfail (`test_a_saturating_result_does_not_launder_its_poison`). Closing it means treating a dropped unit like an unexaminable read, which is the owner's call.

### What it costs, corrected (milestone review, 2026-10-05)
Rerunnable: `scripts/value_origin_measurements/atom_cost.py`.
```
xaidr from: ./xaidr
5 MB (5,000,000 chars), core value-origin cost per path:
  test_truncation_bypass's own input ('(a|a)' x n/5)     input     617 ms (   123 ns/char) | result     522 ms (   104 ns/char) | argument     497 ms (    99 ns/char)
  real prose (benign_longform's largest doc, repeated)   input     574 ms (   115 ns/char) | result     568 ms (   114 ns/char) | argument     561 ms (   112 ns/char)
  ADDRESS-DENSE ('x.co ' repeated): the worst case       input    8520 ms (  1704 ns/char) | result    7245 ms (  1449 ns/char) | argument    7309 ms (  1462 ns/char)
END TO END sensor.scan(test_truncation_bypass's 5 MB input): off 1374 ms, record 1883 ms, delta +510 ms
benign_longform (24 docs, 10,100,008 chars): input 2400 ms total, 100 ms/doc | result 1698 ms total, 71 ms/doc | argument 1485 ms total, 62 ms/doc
```
**The number the owner asked for:**
- On ordinary text, atom extraction is about 100–120 ns/char, so about +0.5 s on a 5 MB value per path.
- **On address-dense text it is ~1.5 µs/char, about 7–8.5 s per 5 MB on each of input, result and argument, with no bound.** An attacker chooses that text.
- `test_truncation_bypass`'s own input gains +510 ms end to end. That test still passes locally and on CI's base jobs.

Whether to bound the atom pass, with a cap that would fail visibly, is the owner's ruling. Nothing here works around it.

## The atom pass is bounded by WORK (owner, 2026-10-06)

> "Bound the atom pass by WORK, not by input position. The timing test is right; the unbounded ruling that broke it was mine." Option (c), relaxing the size guarantee, is refused: "lets an attacker choose how long the scan takes".

- **The budget.** Each seam call gets `ATOM_WORK_BUDGET = 500,000` units: 1 per scanned char, plus `ATOM_COST = 64` per extracted atom. The weights come from the measured ~100 ns/char and ~7 µs/atom.
- **How it runs.** Values are scanned in whitespace-aligned chunks of 16,384 chars. The walk that collects the skipped strings is bounded by the same budget.
- **When the budget runs out.** The rest is not scanned, and the call reads **`extraction_incomplete`** (verdict `not_evaluated`, row `not_recorded`), which **does not block**. For an argument it says so directly; for a result or input it says so on a later miss. It outranks every other non-blocking bound, because a destination may have been missed.
- **A faster pre-filter (option b) was not adopted.** It was not measured.

**Cost under the budget** (`scripts/value_origin_measurements/atom_cost.py`):
```
xaidr from: ./xaidr
budget: ATOM_WORK_BUDGET=500,000 units per seam call; 1/char + ATOM_COST=64/atom; chunks of 16,384 chars
5 MB (5,000,000 chars), core value-origin cost per path:
  test_truncation_bypass's own input ('(a|a)' x n/5)     input     157 ms (    31 ns/char) | result      59 ms (    12 ns/char) | argument      53 ms (    11 ns/char)
  real prose (benign_longform's largest doc, repeated)   input      74 ms (    15 ns/char) | result      60 ms (    12 ns/char) | argument      56 ms (    11 ns/char)
  ADDRESS-DENSE ('x.co ' repeated): the worst case       input     244 ms (    49 ns/char) | result     163 ms (    33 ns/char) | argument      70 ms (    14 ns/char)
END TO END sensor.scan(test_truncation_bypass's 5 MB input): off 1361 ms, record 1404 ms, delta +43 ms
benign_longform (24 docs, 10,100,008 chars): input 1859 ms total, 77 ms/doc | result 1207 ms total, 50 ms/doc | argument 963 ms total, 40 ms/doc
NOT the atom pass -- the EXAMINED bound itself: a result of 64 leaves x 64 KiB, address-dense: result 6254 ms
```
- **The 5 MB bomb end to end: +43 ms** (1.36 → 1.40 s). It was +510 ms unbounded, which failed CI at 2.59 s against 2.5 s.
- **The worst case under the budget, address-dense text: about 0.25 s per call** on the input path, 0.16 s on the result path and 0.07 s on the argument path. It was 7–8.5 s. Most of what remains is the EXAMINED part: the 64 KiB input window, and a result leaf's 64 KiB prefix.
- **NOT met, and outside this ruling:** the examined bound for a RESULT is itself up to 64 leaves × 64 KiB of full examination. With address-dense text that costs **6.25 s**, so address-dense text can still reach seconds through the examined part. This predates the atom pass (V-15). It is reported for the owner's ruling and not changed here.

**Block rate after:** benign_longform is unchanged at 7/24 and 8/24, all `untrusted_source`. Four calls per pass now read `extraction_incomplete`:
```
benign_longform (24 generated documents, 90k..1.4M chars), ENFORCE, block mode:
  P-flow-I                     calls=   24  would block=   7  rate=29.17% | benign_longform: 7/24 [('argument_bound', 13), ('extraction_incomplete', 4), ('untrusted_source', 7)]
  P-flow-R                     calls=   24  would block=   8  rate=33.33% | benign_longform: 8/24 [('argument_bound', 12), ('extraction_incomplete', 4), ('untrusted_source', 8)]
  P-seam                       calls=   24  would block=   8  rate=33.33% | benign_longform: 8/24 [('argument_bound', 12), ('extraction_incomplete', 4), ('untrusted_source', 8)]
```

**The 4,001 vs 3,999 cliff is a KNOWN ARTEFACT** (owner, 2026-10-06), re-checked after the budget change: it persists. The budget limits only very long values. The cliff comes from C-8's whole-leaf rule meeting atom extraction past 4,000 chars. Pinned by `test_known_artefact_the_4000_char_cliff`.

## The ledger has two budgets (owner, approved 2026-10-06)
- **Budgets:** destinations keep `LEDGER_MAX_ENTRIES = 10,000`; the principal's key n-grams get their own `LEDGER_MAX_NGRAMS = 65,536`, sized to the 64 KiB n-gram window (a full window yields at most ~49K). A 17 KB prompt no longer fills the ledger.
- **Known gap, named here as the owner asked:** a tool result naming more distinct addresses than 10,000 still saturates the destination budget. Its whole write, poison included, is dropped, and saturation does not block, so **the poisoned destination is laundered and the call to it is allowed.** It is pinned by the strict xfail `test_a_saturating_result_does_not_launder_its_poison`.

## Why an unexaminable block carries TWO rule ids (owner, 2026-10-06)
A `result_unread` block carries **`ORIGIN_UNEXAMINABLE_SOURCE`** (category `unexaminable_source`) AND **`intent.value_origin_untrusted`**.
- **The first says WHY:** a source could not be examined. `ORIGIN_UNTRUSTED_DESTINATION` would be a false statement.
- **The second is the audit id the Brain-side spec defines (C-19).** The Brain half becomes the intent lens, which filters on it.
- Dropping the second on one path (58d7f64–3f5bf94) hid these blocks from anything filtering on it. It is restored alongside, not instead.
