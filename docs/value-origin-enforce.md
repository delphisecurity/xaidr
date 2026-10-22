# Value origin ENFORCE: what it blocks and what it costs

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

ENFORCE ships **off**. The default is `value_origin="record"`, which reports and
never moves an action. Turn on `value_origin="enforce"` once
`value_origin_sources` designations exist for the tools whose results you trust.
The rules behind every value below are in
[value-origin-rulings.md](value-origin-rulings.md).

## What blocks

| wire value | category | rule ids |
|---|---|---|
| `untrusted_source`: the destination traces to an untrusted source | `untrusted_destination` | `ORIGIN_UNTRUSTED_DESTINATION`, `intent.value_origin_untrusted` |
| `result_unread`: a tool result in the flow was an unread network response, and the destination traces to nothing recorded | `unexaminable_source` | `ORIGIN_UNEXAMINABLE_SOURCE`, `intent.value_origin_untrusted` |
| `write_dropped`: a destination write to the flow's ledger was lost (the ledger was full, or recording faulted), and the destination traces to nothing recorded | `unexaminable_source` | `ORIGIN_UNEXAMINABLE_SOURCE`, `intent.value_origin_untrusted` |

- **Monitor mode** gives `flagged` instead of `blocked`.
- **It runs before** the circuit breaker, the gates and detection, so the block
  holds on the fail-open paths too. It is not counted by the circuit breaker: if
  this layer could trip the breaker, an open breaker would turn detection off
  generally.
- **Why an unexaminable block carries two rule ids.** `ORIGIN_UNEXAMINABLE_SOURCE`
  says why: a source could not be examined, so `ORIGIN_UNTRUSTED_DESTINATION`
  would be a false statement. `intent.value_origin_untrusted` is the audit id the
  intent lens filters on, carried alongside it.
- **The zero-designation warning.** An ENFORCE sensor with no designations logs
  one warning at construction, saying what will be blocked (or flagged, in
  monitor mode).
- **Everything else is visible and does not block:** `argument_bound`,
  `result_truncated`, `input_truncated`, `ledger_saturated` (with a loud warning)
  and `extraction_incomplete`. A positive `untrusted_source` finding outranks
  every one of them.

## What it costs on benign traffic

Measured with `scripts/value_origin_measurements/q13_block_rate.py` on this
repository's corpora, with no designations, ENFORCE in block mode:

| corpus | input-derived | result-derived |
|---|---|---|
| benign (456-row corpus) | 0/83 | 5/83 |
| benign_prose | 6/97 | 7/97 |
| benign_a2a | 0/64 | 4/64 |
| benign_templates | 0/12 | 0/12 |
| benign_longform | 7/24 | 8/24 |

Every benign block above is `untrusted_source`. With no designations every
destination a tool result names is untrusted, so every call to one blocks.

### What each benign block is, and what prevents it

| rows | destination | what prevents it |
|---|---|---|
| benign_prose 002, 004, 034, 041, 045, 058 (input-derived) and the same rows plus 055 (result-derived) | attack URLs and endpoints that the prose quotes | nothing should: a call to a destination an attack text names is a correct block |
| benign 034 | `https://api.github.com/repos/org/repo` | designate the tool that returned it (`MatchKind.ANY`) |
| benign 035 | `https://api.example.com/health` | designate the docs reader that returned it, or a `URL_PREFIX` designation on the docs host |
| benign 066, 067, 068 | `s3://our-public-assets/`, `https://api.internal/health`, `https://reports.internal/q3.pdf` | designate the reading tool |
| benign_a2a, 4 rows | destinations named in A2A result bodies | designate the tool that produced them |
| benign_longform, 7 input-derived | URLs in documents the input scan flags | see "A flagged input" below |
| benign_longform, 8 result-derived | URLs in documents read as tool results | designate the reading tool |

A designation works through every identified seam: the LangChain and MCP
after-hooks, `_scan_tool_result`, and the public
`scan(text, direction="tool_result", tool=..., arguments=...)`. Both keywords are
keyword-only, and `tool=` is trusted as given, so it must come from the host's
own dispatch, never from model output or content. Without `tool=` a read is
nameless and untrusted. A read made only through `protect_tools` records
`result_blocked=None` and is untrusted.

### A flagged input records its destinations untrusted

When the input scan flags the principal's input, every destination candidate in
it is recorded `untrusted_source`, and no designation covers an input. A benign
input the scanner flags (prose that quotes attack URLs, a security write-up, an
incident report) therefore makes the user's own destinations block. The six
input-derived benign_prose rows are this shape, and so are benign_longform's
seven: three documents flagged `oversized_input` and four flagged `pii_detected`
or `data_exfiltration`, each containing URLs. This is one reason ENFORCE ships
off: the scanner's false-positive rate on inputs becomes value origin's block
rate on the user's own destinations.

## Bounds, and what happens past each

| bound | wire on a destination that traces to nothing | past the bound |
|---|---|---|
| an argument leaf over 4,000 chars, more than 64 argument leaves, nesting deeper than 6 | `argument_bound` | a skipped value short enough is read whole; the skipped parts are searched for destination atoms; each is evaluated |
| a tool-result leaf over 65,536 chars, more than 64 result leaves, nesting deeper than 6 | `result_truncated` | the skipped parts are searched for atoms, and each is recorded with the result's origin |
| a principal input over 65,536 chars | `input_truncated` | atoms are recorded from all of it; key n-grams from the first 64 KiB |
| the atom pass's work budget | `extraction_incomplete` | the rest is not scanned |
| the ledger's destination budget (10,000) | `write_dropped` (blocks) | the write is dropped whole |
| the ledger's key n-gram budget (65,536) | `ledger_saturated` | the n-gram write is dropped |
| an unread network response | `result_unread` (blocks) | it is passed on unread, so its stream is never consumed |

- **Work budgets.** The atom pass past a bound costs 1 unit per scanned
  character and 64 per candidate examined, accepted or not, at 500,000 units per
  seam call (`ATOM_WORK_BUDGET`), in whitespace-aligned chunks of 16,384 chars.
  The walk that collects skipped strings is charged to the same budget. A
  result's examined pass (up to 64 leaves of 64 KiB) is charged the same way at
  1,000,000 units per result (`EXAMINED_WORK_BUDGET`), and the examined walk has a
  65,536-node budget, so width cannot escape it.
- **Measured cost under the budgets** (`scripts/value_origin_measurements/atom_cost.py`):

  ```
  5 MB, core value-origin cost per path (500,000 units, 1/char + 64/candidate examined):
    x.co (accepted atoms)                    input    239 ms | result    157 ms | argument     67 ms
    x.zz (rejected candidates)               input    109 ms | result     57 ms | argument     24 ms
    e-acute.e-acute (non-ASCII, rejected)    input    178 ms | result    112 ms | argument     38 ms
    6M-wide dict argument                    argument    434 ms
  examined pass, worst shape found:
    128 x 64 KiB distinct IDN URLs (examined + past the bound)         826 ms
  ```

  End to end, a 5 MB input costs about 0.1 s more with value origin on.
- **The two ledger budgets.** Destinations and key n-grams have separate budgets,
  so key n-grams never take a destination's place. Ordinary text yields at most
  about 49,000 n-grams from a 64 KiB input; 1-char distinct tokens can yield
  125,907 and fill the n-gram budget (`ledger_saturated`, no block). Every benign
  document in this repository, read as tool results in one flow, uses 1,391
  destination entries, 13.9% of the destination budget, and none of the 768
  benign documents trips `write_dropped` alone. A flow that names more than
  10,000 distinct destinations (a crawl across many link-heavy pages) reads
  `write_dropped` for a destination it then cannot trace, and that blocks.
- **Whole values and atoms.** An argument leaf decides the wire only if its
  whole value is one destination (or a mailbox list). A leaf that is not is still
  scanned for destination atoms, and what that finds is OBSERVED: each atom is on
  `CallVerdict.observed` with its origin, and never decides the wire, the verdict
  or an action. Past a bound a value short enough is read whole and its atoms
  decide, so a value names the same destinations wherever it sits. So a 3,999-char
  email body that quotes a URL decides `no_destination` and observes the URL, and a
  4,001-char one decides on the URL it quotes; pinned by
  `test_known_artefact_the_4000_char_cliff` and `tests/test_value_origin_padding.py`.
- **A tool that returns a raw response object** (`httpx.Response`,
  `requests.Response`, an unpreloaded `urllib3.HTTPResponse`) makes a later call
  whose destination traces to nothing block, as `result_unread`. Return the read
  body (`response.text`), which value origin then reads.

## Requests on reused threads

A value-origin ledger belongs to the request it is bound in and closes when that
request ends, so one user's principal authority never reaches another user's
request:

- each `ThreadPoolExecutor` job is a request, so a pool thread starts every job
  with no earlier job's ledger, including one a `begin_flow()` without
  `clear_flow()` bound;
- each CrewAI kickoff and Agents SDK run hooked by `protect()` is a request;
- each fresh `xaidr.flow()` is a request;
- `with xaidr.request_scope():` marks one for a server the sensor cannot see,
  such as a loop that handles request after request on one thread.

A run hooked inside another hooked run scans its input and does not record it as
principal input, because that input is the outer run's model text. Pinned by
`tests/test_value_origin_reuse.py` and `tests/test_value_origin_request_scope.py`.

## The macOS resolver's readings

The core reads the macOS resolver's readings (a leading-zero dotted quad read as
decimal, an IPv6 literal's IPv4 tail read the same way, one number above
2**32 - 1 wrapped modulo 2**32) on every platform. Measured on 24,466 files of
real text on a macOS machine (`docs/evidence/macos-widening-fp-corpus.json`):
the number-above-2**32 shape changes 0 actions, and the leading-zero shapes occur
in none of them.
