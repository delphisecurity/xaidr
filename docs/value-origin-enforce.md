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
| input-derived, benign_prose 002, 004, 034, 041, 045, 058 | `evil.tld/x.sh`, 169.254.169.254 credentials (×2), `metadata.google.internal` token, `x.io/i.sh`, `x.io/i` | **Nothing should.** These are attack URLs that benign prose quotes; the harness builds a call to every URL in the text, and blocking a POST to them is correct. **But the property behind it is a DESIGN GAP:** these destinations come from a PRINCIPAL input that L1 flagged, which V-9 makes untrusted. Designations cover tool reads only, so a benign input that L1 flags (a detection false positive) makes every destination it names block. There is no designation-shaped remedy: only spans, or fixing the detection false positive. |
| result-derived, benign_prose 002, 004, 034, 041, 045, 055 (`s3://exfil-bucket`), 058 | the same attack URLs, plus `s3://exfil-bucket` | **Nothing should.** These are attack URLs quoted in prose, so a correct block. |
| result-derived, benign 034 | `https://api.github.com/repos/org/repo` | **Through a NAMED seam:** designate the tool that returned it (e.g. a GitHub API tool, `MatchKind.ANY`). **Through the public seam the harness used: nothing can.** |
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
- **benign_longform's block rate is not measured.** Its 24 calls were each the
  whole document passed as one over-length argument. See the evasion above.

## The benign_longform anomaly, explained (owner condition 3)

**Recording was not failing.** Each document's result recorded up to 67
destinations. The harness's `calls_for` built exactly ONE call per document:
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
- implements no keyed variant, since nothing defines it.

All three names are constants in `xaidr/sensor.py`.
