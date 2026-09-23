# A fail-closed option for the sensor

**Measure, group, propose. Nothing is built here.** Same posture as
`asi_battery/BOUNDARY_GAP.md`. Branch `design/fail-closed-option`, off
`origin/main` (`0a99741`) — not local `main`, which was 3 commits stale.

External reviewers name fail-open as a weakness. Fail-open is the right
*default* for an in-process control: a scanner bug must not take down the host's
production traffic. The gap is that the operator has no choice. This document
enumerates the sites (§a), proposes the grouping (§b), and measures what each
group would cost on the committed benign pools (§e) — including, and mostly,
where that measurement is not possible.

**The default does not change.** Every group is opt-in and defaults to open.

---

## a. Every fail-open site in the package

173 `except` clauses. They are not 173 decisions. Grouped by *what failed*,
*what the caller gets today*, and *what closed would mean at that specific
site*.

### A — the artifact the sensor was built from is not what the operator has

Fires at import or construction, before a single request. The operator is at a
deploy log, not in a customer incident.

| # | Site | What fails | Caller gets today | Closed would mean |
|---|---|---|---|---|
| A1 | `scanner/l1.py:257-270` | `all-l1-rules.json` / `output-l1-rules.json` missing or corrupt | `print` warning; **empty ruleset**; every scan runs with no regex layer | refuse to construct |
| A2 | `scanner/l2.py:33-43` | `dangerous-intents.json`, `composite-rules.json`, `attack-chains.json` corrupt | `print`; empty list | refuse to construct |
| A3 | `authz/classifier.py:52-57` | `impact-classes.json` corrupt | `print`; **defaults only** — every action classifies `unknown`/`medium` | refuse to construct |
| A4 | `scanner/normalizer.py:66-78` | `typo-keywords.json` corrupt | `print`; normalization silently disabled | refuse to construct |
| A5 | `l1.py:342`, `l2.py:62`, `classifier.py:68,82,94,106` | ONE regex fails to compile | `print`; that rule is dropped, the other ~159 load | raise, as `UnknownRuleCategory` already does at `l1.py:289` |
| A6 | `local_policy.py:107-132` | PyYAML absent / file unreadable / policy malformed | `logger.warning`; `None`; **detection-only** | refuse to construct when a policy was *named* |
| A7 | `local_policy.py:150-153` | `set_policy()` handed a malformed dict | warning; `None`; returns `False` | already semi-closed — the return value is readable |
| A8 | `scanner/nano.py:837-840`, `scanner/local.py:1089-1092` | nano inference raises / non-finite probability | `p_raw=0.0`, family `none` — the signal the operator enabled is silently absent | block, or refuse to construct on repeat |
| A9 | `scanner/local.py:390-398` | an escalator's `health()` reports unhealthy or raises | logged; **the link is kept anyway** | refuse to construct |

Note A8's asymmetry: a hash-mismatched nano artifact already **raises** at
construction (`nano.py:745`, `_verify`), but a nano that loads and then throws
on every inference degrades in silence. Same control, two postures.

### B — a control the operator installed did not run

Per-call. Zero of these sites are live on a bare sensor.

| # | Site | What fails | Caller gets today | Closed would mean |
|---|---|---|---|---|
| B1 | `sensor.py:1052-1056` | extension `gate()` raises | `_extension_failed`, skip, detection proceeds | refuse the call |
| B2 | `sensor.py:1082-1088` | `transform_verdict()` raises (non-contract) | skip; verdict unmodified | refuse the call |
| B3 | `sensor.py:740-742` | `subject_trust()` raises | `None` → a `trust_below` policy rule **never fires** | refuse the call |
| B4 | `sensor.py:2710-2713` | `blocked_urls()` raises | that extension's destinations are **absent from the blocklist** | refuse the call |
| B5 | `sensor.py:3521-3526` | `destination_policy()` raises | skip; operator blocklist still runs | refuse the request |
| B6 | `escalation.py:135-170` | escalator raises or exceeds `timeout_ms` | local verdict stands, `ESCALATION_SKIPPED` + reason | refuse the call |
| B7 | `sensor.py:883-890, 896-902, 939-948, 1140-1141, 1186-1187, 1215-1217` | breaker state read or counter raises | `"closed"` / counter inert — `circuit_state` keeps reporting health | refuse the call (**not** open the circuit — see §b) |
| B8 | `autopatch/core.py:126-160` | a patched framework hook raises | `logger.warning`; **the tool/HTTP call proceeds unscanned** | refuse the call |
| B9 | `autopatch/core.py:375-390`, `frameworks.py:615` | a seam cannot be patched | `unpatchable()` manifest record; that boundary is never scanned | refuse to construct |

B7's design constraint is already written down at `sensor.py:1143-1174`: the
counter fault is deliberately fail-open because "a breaker that takes the agent
down when its own bookkeeping fails is worse than one that stops counting."
That reasoning is about the *breaker's* response, not about the operator's
choice, and a `fail_closed` option is exactly the operator making it.

### C — an input defeated a parser bound

The only class where the **attacker chooses** whether the site fires.

| # | Site | Bound | Caller gets today | Closed would mean |
|---|---|---|---|---|
| C1 | `a2a_structural.py:204-212, 332-333` | `_MAX_NEST_DEPTH=8` | `a2a_nested_depth_exceeded` @ **0.35** (flag band); the unwalked remainder is never inspected | block |
| C2 | `a2a_structural.py:196-198, 219-221, 334-335` | `_MAX_NEST_NODES=64`, `_MAX_LIST_ITEMS=32` | `a2a_nested_breadth_exceeded` @ 0.35 | block |
| C3 | `a2a_structural.py:542` | `_MAX_METADATA_NODES=512` | folded into the breadth signal | block |
| C4 | `l1.py:173-203`, `sensor.py` callers | `L1_MAX_SCAN_CHARS=100_000`, `MAX_SCAN_WINDOWS=8`, `TOTAL_SCAN_BUDGET_SEC=1.0` | `LLM01_oversized_input` flag; **the tail past the budget is never scanned** | block |
| C5 | `l1.py:393-399, 461-468` | `_L1_SCAN_BUDGET_SEC=0.5` | `LLM04_scan_budget_exceeded` @ 0.25; remaining rules skipped | block |
| C6 | `l1.py:436-442, 453-460` | `_L1_RULE_SLOW_SEC=1.0` | `LLM04_pathological_pattern` @ **0.65** | **already closed** at the default 0.60 threshold |
| C7 | `sql_parse.py:86-95, 900-910` | `MAX_SQL_CHARS=20_000`, `MAX_STATEMENTS=32`, `_MAX_TOKENS=20_000` | `_unparsed_shape` → `statement="unparsed"`, matched by `sql.unparsed_input` at **critical, `detect: None`** — classified, never blocked | promote to a detection |
| C8 | `sql_parse.py:713` `_predicate_state_tokens` | predicate not settleable | `predicate="unknown"` → `sql.unbounded_mutation`, critical, `detect: None` | promote to a detection |
| C9 | `classifier.py:536, 613-617` | `_MAX_CANDIDATE_VALUES=64`; `RecursionError` on a deep argument tree | the un-walked values are never classified | block |
| C10 | `command_parse.py:500-507, 548-552, 616-623, 818-823, 137-140` | unbalanced quotes, `_MAX_TOKENS_PER_SEGMENT=512`, `_MAX_INPUT_CHARS=16_384`, `_MAX_PAYLOAD_DEPTH=2`, undecodable base64 | `parse_degraded` — the segment may contribute a class but **never a finding**, and never `critical` | allow a degraded segment to block |
| C11 | `url_parse.py:196, 249-251` | `MAX_URL_CHARS=4_000`; any parse fault | `None` — the value is not a URL as far as the scanner is concerned | block |
| C12 | `sensor.py:1678-1683, 3159-3165`, `_a2a_detect.py:145-149` | `json.loads` raises (incl. `RecursionError`) at depth | `body=None`; scanned as **raw text**, structural layer never runs | block |
| C13 | `sensor.py:403-410` | `json.dumps` fails on the argument tree | `repr`, then `"<unrenderable-arguments>"` | block |

C6 and C7 are the proof the group is coherent: the codebase has already reached
for fail-closed at two bound sites, one at a time, with different mechanisms
(a block-band score; a synthetic shape plus a rule), and stopped there. C7/C8
are only *half* closed — they name a critical class that no `detect` block
enforces, so today they are closed **only for an operator who has written a
policy**.

### D — the sensor's own code raised

| # | Site | Caller gets today | Closed would mean |
|---|---|---|---|
| D1 | `sensor.py:1421-1436` `scan` | `allowed` 0.0, `SCAN_FAILED_OPEN`, `degraded: True` telemetry, WARN | block |
| D2 | `sensor.py:1601-1614` `scan_a2a` | same | block |
| D3 | `sensor.py:1816-1832` `scan_tool_call` | same | block |
| D4 | `sensor.py:3474`, catch at `3629-3643` | WARN; **the operator's own blocklist never ran** for this request | block |
| D5 | `sensor.py:413-427` `_coerce_scannable` → `_emit_not_scannable` (`1279-1313`) | `allowed` 0.0, `INPUT_NOT_SCANNABLE` | block, or raise `TypeError` |
| D6 | `classifier.py:354, 427, 493, 530, 638, 697, 734, 769, 891` | `[]` / `None` — no structural finding | block |
| D7 | `command_parse.py:284-290` | `[]` — "no structure available" | block |
| D8 | `sql_parse.py:910-922`, `url_parse.py:249-251` | `[]` / `None` (SQL already partially closed via `_statement_head`) | block |
| D9 | `sensor.py:3309-3320` `_extract_response_text` | `''` — the response is **not scanned** | block |
| D10 | `privilege_tiers.py:119-126` | `None` → the tier is unconfigured rather than wrong | keep open (a *config* parse, and `validate_tier` already raises for a bad constructor value) |

### N — observability. Never offered as an option.

`sensor.py:985, 1023, 1354, 1390, 3465-3471`; `telemetry.py:136-139, 173-185,
224-230`; `reporters.py:157, 175, 193, 222, 246, 318, 322, 328, 350, 357, 405,
414, 426, 455, 465, 498, 505`; `trace_context.py:95, 106`;
`autopatch/manifest.py:174, 190, 202`.

These never touch a verdict. A `fail_closed` that blocks production traffic
because a webhook is down is an availability bug with a security-sounding name.
The reviewers' phrase "the sensor fails open" covers these sites too; conceding
them would be wrong. **They stay open unconditionally and the option does not
list them.**

---

## b. The grouping

Four groups. The organizing question is **not** severity — it is *who can fix
this, and when*. Four different answers, four groups.

```
Sensor(fail_closed=())                      # the default. unchanged.
Sensor(fail_closed=("controls",))           # B
Sensor(fail_closed=("controls", "bounds"))  # B + C
Sensor(fail_closed=("artifact",))           # A  — refuses to CONSTRUCT
Sensor(fail_closed=("internal",))           # D
```

### G1 `artifact` — A1–A9, B9. **This is not a traffic verdict.**

Closed means `DelphiSensor.__init__` **raises**. It does not mean requests
block.

That is the whole reason the mandated question has a clean answer, so, plainly:

> **No grouping proposed here blocks traffic when a rule file is corrupt.**

G1 makes the sensor refuse to *start*. The host then makes its own choice —
crash, or run unprotected and log it — once, at deploy, with a stack trace
naming the file. Constructing and then blocking every request would be strictly
worse in three ways. It converts a packaging defect into a production outage
found by customers. It gives the operator no signal saying *which* asset is
broken, only a wall of blocks. And it is dishonest: a `blocked` verdict asserts
"this content is dangerous", and a corrupt `all-l1-rules.json` says nothing
whatever about the content. **Any grouping that put rule-asset loading into a
traffic-verdict group is wrong and I would reject it.**

G1 is also the ADV-2 posture the codebase already uses everywhere else in the
constructor — `enforcement_mode` (`enforcement.py:resolve`), `privilege_tier`
(`sensor.py:487`), `circuit_breaker` (`652`), `extensions` (`541`), the nano
artifact hash (`nano.py:745`), a duplicate policy-condition key (`784`). A
security control handed something it does not understand fails at construction.
Seven constructor arguments already obey that. The seven rule assets do not.

A5 deserves its own line: today one regex failing to compile is a single
`print` and 159 rules still load. `l1.py:278-297` already argues that a rule
silently half-disabled by a typo must be a build error, and raises
`UnknownRuleCategory` for exactly that. A rule that fails to *compile* is the
same defect with a different cause, three lines further down, and it prints.

### G2 `controls` — B1–B8. Refuse the call.

The operator paid for a control and the verdict was computed without it. This
is the group the reviewers are actually asking for.

Separated from G3 and G4 because the faults are in code the operator **added**.
That gives it a property nothing else here has: **on a bare open sensor, G2 is
a no-op by construction** — `self._extensions` is empty, `self._breaker` is
`None`, `self._escalators` is empty, nothing is autopatched. Turning it on
cannot change a single verdict until the deployment installs something. That
makes G2 the first group an operator should be told to enable, and it is the
reason I would not merge it into G4.

One constraint carried forward: B7 closed must mean *refuse this call*, never
*open the circuit*. Opening a circuit halts every call for the cooldown, and
`_breaker_delegation_tick` (`sensor.py:1189-1211`) already argues at length
that a breaker which halts a healthy service manufactures the cascading failure
it exists to contain. The same argument applies to the breaker's own
bookkeeping.

### G3 `bounds` — C1–C13. Block the input.

This group exists separately because of one asymmetry: **every other group's
trigger is an accident; this one's is a lever.** An attacker chooses to nest
nine deep, to pad past 100 000 characters, to prepend 33 harmless statements,
to unbalance a quote. Today most of those levers point the wrong way — nesting
past depth 8 converts whatever sat at level 9 into a 0.35 flag.

It must not be merged with G2 because it is the only group with a real
false-positive cost on honest traffic: a large document, a long migration, a
deep task envelope. That cost is measured in §e — and mostly cannot be.

G3 should **compose with the policy engine, not duplicate it.** C7/C8 already
classify at `critical` with `detect: None`, so an operator with
`match: {impact_tier: [critical]} → block` has already closed them. The
implementation should promote bound signals into the *classification* path
wherever one exists, and only synthesise a direct block where none does.

### G4 `internal` — D1–D9. Block.

The group the reviewers name first, and the one to recommend **last**. Its
trigger is a bug in our code, which means an operator enabling it is betting
their availability on our test coverage. It has to be its own group precisely
so that an operator can take G2 and G3 without taking this.

D4 (`_check_destination`) is the odd one: it is the only D-site whose fail-open
skips a check that has **already decided something** — the operator's own
`blocked_urls` list and their deny-destination policy. It is arguably a G2
member. Flagging it rather than deciding it; it is a grouping question, and the
grouping is what needs agreeing.

D10 stays open in every group. It is a config parse, and `validate_tier`
already raises for a bad constructor value.

### What is deliberately NOT a group

**"Unknown classification" is not a fault and must never be in any group.**
`classify()` returns `("unknown", "medium")` for an action no rule describes.
Measured over the four benign tool-call pools:

```
benign tool-call items by (impact_class, tier)    n=368
  ('unknown', 'medium')   280        ('read',   'low')     30
  ('unknown', 'high')      10        ('send',   'medium')  12
  ...
unknown-class benign items: benign_tc 139, benign_disc 33,
                            benign_dml 50, shell.benign 68   -> 290 / 368
```

**290 of 368 benign tool calls (79%) classify as `unknown`.** Any group that
treated "we could not classify this action" as a fault to fail closed on would
block four benign tool calls in five. The operator knob for this already exists
and is correctly placed: `defaults.unclassified` in the policy file
(`local_policy.py:28`). It is a policy decision about *coverage*, not a
degradation of the sensor, and folding it into `fail_closed` would be the same
category error as folding in the telemetry sites.

---

## e. What each group would cost — measured, and where it cannot be

Harness: `scripts/corpus_diff.py:87-147` pool list, benign rows only, plus
`benign_a2a/nested.jsonl` (which `corpus_diff` does not carry). 814 rows over
725 distinct items — `shell.prose` is scanned on both the input and tool
surfaces and counted twice. Sensor built exactly as `corpus_diff.py:92` builds
it.

```
POOL SIZES (benign only)
  asi.benign             n= 146  blocked_today=1
  benign_a2a             n=  60  blocked_today=0
  benign_disc            n=  50  blocked_today=0
  benign_dml             n=  50  blocked_today=0
  benign_tc              n= 190  blocked_today=0
  heldout.benign         n=  50  blocked_today=1
  shell.benign           n=  78  blocked_today=0
  shell.prose            n=  89  blocked_today=1
  shell.prose.tool       n=  89  blocked_today=0
  shell.template         n=  12  blocked_today=0
  TOTAL n=814

FAIL-OPEN SITE REACHABILITY
  E1.scan_catch                    items=   0
  E2.not_scannable                 items=   0
  E3.a2a_walk_bounds               items=   0
  E4.sql_unparsed_bound            items=   0
  E5.sql_predicate_unknown         items=   0
  E6.command_parse_degraded        items=   1  {'asi.benign': 1}
        asi.benign/ASI05-B03  print(sum(range(10)))
  E7.command_parse_crash           items=   0
  E8.url_parse_crash               items=   0
  E10.arg_walk_truncated           items=   0
  E11.policy_load_fallback         items=   0  (+1 at CONSTRUCTION)
  E12.shlex_fallback               items=   0

DEGRADATION RULES ALREADY IN BENIGN VERDICTS
   none
```

### The headline, at design time

**Of the four groups, the committed benign pools could measure exactly one, and
within that one, three of its thirteen sites.**

| Group | benign items that would block | status of that number |
|---|---:|---|
| G1 `artifact` | **0** | true by construction — G1 is not a traffic verdict |
| G2 `controls` | **0** | **BLIND** — every site unreachable in the harness |
| G3 `bounds` | **1 / 814** | partially measured; 5 of 13 sites blind |
| G4 `internal` | **0** | **BLIND** — needs fault injection, not a corpus |

`corpus_diff.py` builds `Sensor(agent_id=..., enforcement_mode="block",
reporter=_NullReporter())`. Measured: `circuit_breaker=None`, `extensions=()`,
`escalators=()`, `enable_nano=False`, no policy file, autopatch never called.
Every G2 and G4 site is off before the first item is scanned. Reporting "G2
costs 0 false positives" from that harness would have been the eighth instance
of the shape `benign_a2a/README.md` documents.

That is what the two shipping conditions were for. Both are now closed.

---

### Condition 1 — `controls` and `internal`, measured by sabotage

`tests/test_fail_closed_sabotage.py`. 52 tests, one per site, **each asserted
twice**: open still fails open exactly as before, closed hands back a usable
refusal of the right TYPE.

```
$ PYTHONPATH=. python -m pytest tests/test_fail_closed_sabotage.py -q
52 passed in 0.17s
```

Sites covered — `test_every_control_fault_site_in_the_source_is_sabotaged_here`
counts the `_control_fault(` call sites in the source and fails if one is added
without a test here:

| | Site | Open | Closed |
|---|---|---|---|
| B1 | extension `gate()` raises | `allowed` | refusal |
| B2 | `transform_verdict()` raises | `allowed` | refusal |
| B3 | `subject_trust()` raises | `None` | refusal |
| B4 | `blocked_urls()` raises | list without it | refusal |
| B5 | `destination_policy()` raises | request proceeds | `DelphiBlockedError` |
| B6 | escalator raises / times out | local verdict | refusal |
| B7 | breaker state read + all 3 counters | `"closed"` / inert | refusal ×4 |
| B8 | nano inference raises | signal silently absent | refusal |
| B8′ | autopatch tool seam | call runs | refusal string |
| D1–D3 | scan / scan_output / scan_a2a / scan_tool_call | `SCAN_FAILED_OPEN` | refusal ×4 |
| D4 | `_check_destination` raises | blocklist skipped | `DelphiBlockedError` |
| D5 | wrong-typed input | `not_scannable` | **stays open** (§f7) |

**Three things the sabotage found that a corpus could not have.**

1. **`_extension_failed` deduplicated its fault handling, not just its log.**
   The ERROR line is once per (extension, hook) — correct, a broken hook should
   not produce fifty lines. But the dedup `return`ed EARLY, so a refusal placed
   after it would have fired on call 1 and silently allowed calls 2..N. Logging
   and refusing are different questions and now have different lifetimes;
   `test_B1_gate_closed_refuses_EVERY_call_not_just_the_first` is the gate.
2. **The first draft of the harness sabotaged the wrong thing.** It set
   `sensor._scanner.scan = _boom` for all four entry points — but the tool path
   does not go through the content scanner, it calls `classify()` directly. So
   `scan_tool_call`'s OPEN half passed by returning a clean allow **with no
   fault injected at all**. That is the vacuous-gate shape one layer down from
   the corpus blindness, and it is why each site now carries its own sabotage
   function and the open half asserts `SCAN_FAILED_OPEN` is actually present.
3. **Three tests were passing as `skip`.** The escalator and nano sabotages
   skipped when the input did not reach the band — green, and proving nothing.
   Both now have an explicit precondition test
   (`test_B6_precondition_escalatable_input_reaches_the_link`,
   `test_B8_precondition_nano_is_actually_consulted`) that fails loudly if the
   input stops reaching the site. 0 skips.

---

### Condition 2 — the over-length path, measured on a corpus that reaches the cap

`benign_longform/` — 24 items, six realistic shapes, 90 KB to 900 KB. It could
be written convincingly, so C4 ships **supported**, not unsupported. But only
after the corpus rejected the first design.

**The corpus found a defect before ship.** `LLM01_oversized_input` fires on
`len(prompt) > L1_MAX_SCAN_CHARS` and nothing else, so it is on every input past
the cap — including the ones the windowed scan then covers completely. Refusing
on it means refusing a 150 KB contract that was read end to end.

```
NAIVE   (refuse on LLM01_oversized_input)        refused-and-unread 2   refused-but-FULLY-READ 4   allowed 3
SHIPPED (refuse on LLM01_input_tail_unscanned)   refused-and-unread 2   refused-but-FULLY-READ 0   allowed 7
```

(over the 9 of 24 items that are clean at the default posture)

So `scanner/l1.py` gained `LLM01_input_tail_unscanned`, fired by
`LocalScanner._scan_tail` when the windows run out before the text does, and
`_BOUND_SIGNAL_RULES` names that rule and **not** `LLM01_oversized_input`.
"This input is long" is not a bound fault. "There is text in it that nothing
was run against" is.

```
  items                                    24
  wall-clock bounds PINNED; window coverage limit = 796,416 chars
  over the 100,000-char cap              19
    ...FULLY covered by the windowed scan  13
    ...tail never read                     6
  clean at the DEFAULT posture             9
  THE BOUNDS COST, over default-clean items only
    refused, tail genuinely unread          2   (the group working as designed)
    refused, FULLY READ                     0   <- false positives
    not refused                             7
```

**These numbers replace an earlier set (4 covered / 15 truncated / 12 clean /
7 refused-and-unread, and `refused-but-FULLY-READ 2` under the naive signal).**
The earlier figures were measured with the three L1 wall-clock bounds live, so
they described the machine that ran them rather than the corpus; see
`benign_longform/README.md` for the full retraction. **The zero did not move** —
refused-but-fully-read is 0 under either measurement, which is the claim this
section exists to support.

**Two caveats that ship with that zero.**

* **At runtime the boundary is a wall-clock budget, not a length.**
  `_L1_SCAN_BUDGET_SEC` (0.5 s), `_L1_RULE_SLOW_SEC` (1.0 s) and
  `TOTAL_SCAN_BUDGET_SEC` (1.0 s) can each end a scan early on a busy host, and
  the resulting bound signal makes `bounds` refuse. The same document can be
  refused on a loaded host and allowed on an idle one — and on a host loaded
  enough this reaches inputs **under** the 100 000-character cap. Observed, not
  predicted: on a GitHub `ubuntu-latest` runner a 90 000-character benign item
  tripped `LLM04_scan_budget_exceeded` and was refused. Past 796 416 characters
  the window cap decides on any machine; below it, the host does.
  `scripts/longform_bounds.py` pins the clocks so the measurement above is a
  property of the text — the gate must not be a benchmark of the CI fleet.
* **15 of 24 items score on CONTENT at the default posture**, with no group
  closed and nothing to do with `bounds` — `INTENT_exfiltrate_data` on every log
  tail and transcript (an L2 co-occurrence rule: in 90 KB of honest text, *some*
  action word and *some* target word co-occur with near certainty), DLP
  digit-run patterns matching across newlines, and six rules on the full text of
  a pasted policy document. Excluded from the cost above, because counting them
  would blame `bounds` for refusals it did not cause.
  Recorded in `benign_longform/README.md` as their own finding; neither is fixed
  here.

---

### The committed pools, re-measured with each group closed

814 benign rows, after the implementation:

```
fail_closed=()                                  n=814  refused=0
fail_closed=('bounds',)                         n=814  refused=1  ['asi.benign/ASI05-B03#0']
fail_closed=('controls',)                       n=814  refused=0
fail_closed=('internal',)                       n=814  refused=0
fail_closed=('bounds','controls','internal')    n=814  refused=1  ['asi.benign/ASI05-B03#0']
```

The single refusal is `ASI05-B03`, `print(sum(range(10)))` — a Python payload
shell-tokenized into pseudo-names, so `command.parse_degraded`. It is the same
item the design-phase census predicted, and it is a correct refusal: the parser
genuinely could not read it.

The `controls` and `internal` zeros here are **still blind and still not
numbers** — the harness has no extensions, no breaker, no escalators. The
sabotage suite is where those groups are measured. This table is the
zero-movement gate on the DEFAULT, not a cost measurement for those two groups.

### G3, site by site

| Site | Measured | Verdict on the number |
|---|---|---|
| C7/C8 SQL bounds & predicate | max 134 chars vs `MAX_SQL_CHARS=20 000`; max 3 statements vs 32; **0 / 50** produce `unknown`/`unparsed` | **REAL** — the pool was built for this class |
| C10 command parse degraded | **1 / 814** (`ASI05-B03`) | **REAL** — G3's entire measured cost on the committed pools |
| C4 over-length | **0 / 12** default-clean fully-read items refused, 7 / 12 truncated refused | **REAL**, via `benign_longform/`, with the wall-clock caveat above |
| C1/C2/C3 A2A walk | max depth 4 vs bound 8; max nodes 27 vs 64 | **REAL but weak** — proves the bound is clear of honest A2A, cannot price moving it |
| C9 argument-tree walk | max 10 string values vs bound 64 | **BLIND** — 6× short of the bound |
| C11 URL cap | 0 faults; nothing near `MAX_URL_CHARS = 4 000` | **BLIND for the cap** |
| C12 deep-JSON `RecursionError` | 0; max body 3 241 chars, depth 4 | **BLIND** |
| C13 unrenderable arguments | 0; every arg tree is JSON by construction | **BLIND** — the `.jsonl` format forbids the input class |
| C6 pathological pattern | 0 | **BLIND**, and moot: already closed at 0.65 |

Four of nine G3 sites remain blind. They are named here rather than folded into
a headline number, and the group ships with that stated.

### What fail-open costs today, for contrast

G1 has no benign cost, so the only honest way to price it is the detection it
loses when it fires. Per asset, emptied one at a time:

```
                        shell.attacks   heldout.attacks   asi.attacks
                            blocked      blocked/scored     blocked
  rules loaded               165/277        3/50  18/50      9/147
  all-l1-rules.json empty    133/277        3/50  18/50      5/147
  output-l1-rules.json       165/277        3/50  18/50      8/147
  impact-classes.json         90/277        3/50  18/50      9/147
  dangerous-intents.json     165/277        2/50   6/50      7/147
```

`impact-classes.json` alone is worth **75 of 277** shell-attack blocks, and
`dangerous-intents.json` takes held-out scoring from 18 to 6. Today all four
degrade to empty behind a `print` on stdout.

---

## What would end the blindness — and what did

Per group, the measurement work each one needed. **Both conditions are now
closed;** what follows records what they produced.

* **G2 / G4 — a corpus of FAULTS, not of inputs.**
  `tests/test_fail_closed_sabotage.py`, 52 tests, one per site, each asserted
  twice: open still fails open, closed hands back a usable refusal. See §e.
* **G3/C4 — a benign large-document pool.** `benign_longform/`, 24 items from
  90 KB to 900 KB. It found a design defect before ship; see §e and
  `benign_longform/README.md`.
* **G3/C1-C3 — `benign_a2a` items at depth 6–8, not 2–4.** NOT done. The
  present pool proves the bound is clear of honest A2A; it still cannot price
  moving the bound. Recorded as remaining work rather than closed.

---

## c. What a refusal returns

### The answer is: nothing new. That is the whole design.

A fail-closed decision produces an ordinary `ScanResult` — `action="blocked"`,
`category="fail_closed"`, `rules=["FAIL_CLOSED_<GROUP>_..."]`,
`input_status="fail_closed"` — and travels the refusal path each boundary
**already has**. Not one new return path is added anywhere in the package.

That is not minimalism, it is the lesson from 1.9.0 read correctly. A LangGraph
`ToolNode` calls `tool.invoke(tool_call)`, requires a `ToolMessage` back, and
raises `TypeError: Tool <name> returned unexpected type: <class 'str'>` on
anything else; its default `handle_tool_errors` re-raises, so a **correctly
blocked call took the whole graph down**. The bug was not the verdict. The bug
was a verdict travelling a return path whose type contract it did not satisfy.

The lesson people usually take from that is "be careful with the new type". The
lesson that actually prevents it is **do not add one**. Every boundary in this
package already knows how to refuse, and every one of those refusal paths has
been type-audited against its framework:

| Boundary | How it refuses today | Where |
|---|---|---|
| langchain tool (`BaseTool.run`/`arun`) | `ToolMessage` when `tool_call_id` is set, refusal string otherwise | `frameworks.py:240-290` `_langchain_refusal` |
| any tool seam | refusal string via `Halt` | `core.py:463` `scan_tool_boundary` |
| CrewAI | `_PENDING_REFUSAL` contextvar → `before_tool_call` | `crewai.py:99` |
| Haystack | `must_halt` check at the component boundary | `haystack.py:222,317` |
| entrypoint / transport / `protect_http` | `DelphiBlockedError` | `core.py:471` `scan_text_boundary` |

All five gate on `result.must_halt` or `result.action`, neither of which cares
what produced the verdict. A `fail_closed` result with `action="blocked"`
satisfies every one of them **unchanged**, which is why implementing (c)
required exactly one edit to the refusal machinery — a branch in
`refusal_text()` so the transcript says something useful.

`tests/test_fail_closed_sabotage.py::assert_usable_refusal` asserts
`isinstance(result, ScanResult)` on every site with the 1.9.0 shape named in
the failure message, so a future change that reaches for a new type fails on 30
tests at once.

### The one thing the refusal text must say differently

Every other refusal in this package is a statement about the CONTENT: your call
was judged and denied. A fail-closed refusal is a statement about the SENSOR:
the judgement could not be made. An agent handed `[BLOCKED] blocked by security
policy (fail_closed)` will reasonably rephrase and retry, which cannot help and
burns a turn. So `refusal_text()` branches on `input_status == "fail_closed"`:

```
[BLOCKED] Tool 'send_email' was NOT executed: the security sensor could not
produce a reliable verdict (FAIL_CLOSED_CONTROL_FAULT) and this deployment is
configured to refuse rather than allow in that case. Retrying will not help;
this is an operator-configured refusal.
```

### Mode applies; the extension transform chain does not

A fail-closed verdict goes through `enforcement.downgrade()`, so **a
monitor-mode sensor still returns `flagged`**. An option that silently turned
monitor into an enforcing mode would be a worse defect than the one it fixes.
It also gives an operator the measurement path: run `fail_closed` in monitor,
watch the `failClosedGroup` telemetry, and see every refusal the posture would
have made on *their* traffic before switching.

It does **not** go through `_run_verdict_transforms` (S6). That chain lets each
extension soften a verdict, and this verdict exists precisely because a
subsystem faulted — in the `controls` case, usually an extension. Routing it
back through the extension chain would let the broken component erase its own
refusal.

### `approval_required`: yes, as an option, for three of the four groups

```python
Sensor(fail_closed=("controls", "bounds"))                    # both -> blocked
Sensor(fail_closed={"controls": "approval_required",          # per-group
                    "bounds": "blocked"})
```

**For.** A deployment that already gates on `approval_required` has a human in
the loop and a route for pending actions — it has *paid* for that
infrastructure. For them a fail-closed that routes to a human is strictly
better than a denial: the action is preserved and recoverable rather than
dropped, and `refusal_text` already emits a distinct, routable message. The
plumbing is all there (`_HALTING_ACTIONS`, `must_halt`, `requires_approval`,
`_ACTION_SEVERITY["approval_required"] = 2`), so refusing to offer it would be
withholding a better answer from the deployments best equipped to use it.

**Against, and why it is not the default.** A deployment with no approval route
that sets it gets a halt with a message nobody reads — indistinguishable from a
block, harder to debug. Worse: `_breaker_observe` deliberately does not count
`approval_required` as a violation (`sensor.py`, "an approval gate is a pending
human decision, not a denial"), so **a persistently broken extension under
`approval_required` produces an unbounded queue of pending approvals and never
trips the circuit breaker.** `blocked` trips it and the agent stops. That is a
real operational difference and it is why `blocked` is the default and this
paragraph is in the release notes.

**`artifact` accepts neither, and `resolve()` raises if you try.** The fault
predates every request, so there is no action for an approver to approve and
no per-action approver to route to. Accepting the value would publish a posture
that cannot exist.

---

## d. The default stays fail-open

`fail_closed=()`. Every group off. Not one line of the scan path behaves
differently from before the option existed, and that is asserted rather than
claimed:

* `test_open_posture_is_the_default_and_unchanged` — the whole option, off.
* `test_default_posture_is_byte_identical_on_this_pool` — over `benign_longform/`,
  the population that can see the code this work touched (`iter_scan_windows`
  now yields a third element; `_scan_tail` counts coverage).
* The committed pools: **814 benign rows, 0 refused at the default**, and the
  per-pool block counts are identical to the pre-change run (§e).

Mechanically, `fail_closed=()` resolves to a shared empty `FailClosedConfig`,
every `group in self._fail_closed` is a lookup in an empty dict, and every new
computation — `bound_faults()`, the `_post_scan_gate` checks — is behind that
lookup. Unregistered means unchanged, the same contract `extensions.py` rule 1
already states for the seams.

**Changing the default would be a breaking change for every existing
deployment** — an availability change, arriving without anyone editing
anything, in a release whose notes are about something else. That is precisely
the argument `circuit_breaker.py` already makes for `delegation_rate_threshold`
defaulting to `None`. If it ever changes it is its own major release with its
own notes, and the notes lead with the `approval_required`/breaker interaction
above.

### Release note content (1.18.0)

* **New, opt-in, default off:** `Sensor(fail_closed=...)`, four independent
  groups. Nothing changes unless you pass it.
* **New signal, on by default:** `LLM01_input_tail_unscanned` — fires when the
  windowed scan ran out of budget before the end of an over-length input.
  Additive: it appears alongside `LLM01_oversized_input` in `rules`, in the
  flag band, and changes no verdict at the default thresholds. It exists
  because "this input is long" and "there is text in it nothing was run
  against" were the same rule, and only the second is a security fact.
* **New, on by default:** `Sensor.degradations` — asset load failures,
  unhealthy escalators, faulted extension hooks and inert breaker counters, as
  a list. Previously four `print` calls to stdout and two ERROR log lines.
* **Behaviour change, small:** a fault inside the gate chain
  (`_run_gates`) now fails open with `SCAN_FAILED_OPEN` instead of propagating
  to the host. This closes a hole in the "no scan entry point can crash the
  host" contract that `test_operational_resilience.py` already asserted for
  every other part of the entry point.
* **Not changed:** the default posture, every threshold, every rule asset, and
  every verdict on all 814 committed benign rows.

---

## f. Where fail-closed is NOT implementable

A site that cannot fail closed is a finding for the docs, not a gap to paper
over. This is the same contract `ProtectionManifest` already keeps for
unpatchable seams: the absence is stated loudly, by name, in the artifact the
operator reads. `Sensor.degradations` and this section are that artifact.

### f1. The rule-asset loaders — the fault point cannot be the fail-closed point

`l1.INPUT_RULES` is assigned **at module import**. By the time any sensor
exists, a corrupt `all-l1-rules.json` has already degraded to an empty ruleset.
Making the loader raise means `import xaidr` crashing a host over a JSON file —
and no operator can opt out of that, because at import time there is no
operator object to hold the choice.

So the loader records (`failclosed.record_asset_fault`) and import succeeds;
`DelphiSensor.__init__` applies the choice. **Consequence, stated rather than
hidden: with `artifact` closed, a corrupt asset is caught at the first sensor
construction, not at import.** A host that imports `xaidr` and never constructs
a sensor is not protected by this group.

### f2. A pathological regex — closed can observe, never prevent

In CPython a running `re.search` is a single C call: no signal handler and no
thread can interrupt it (`l1.py`, "A budget can therefore only ever observe
that a pattern WAS pathological"). `LLM04_pathological_pattern` fires *after*
the time has been spent. Fail-closed refuses the call, which is worth doing —
but it cannot prevent the latency, and an attacker who wants to burn 60 seconds
of CPU still burns it. The real fix for a backtracker is a linear pattern, and
that is unchanged by this work.

### f3. The autopatch `_after` hook — the action has already happened

`make_wrapper`'s post-call hook runs after the underlying tool or HTTP call has
executed. Refusing there cannot un-send the request or un-run the tool; it can
only suppress the RESULT. That is meaningful for output DLP and worthless as
prevention, so `internal` closed on an `_after` fault suppresses the response
rather than claiming to have stopped anything. The same is true of
`_extract_response_text` (D9): the bytes already arrived.

### f4. An unpatchable seam — you cannot refuse at a site you do not occupy

When `ctx.try_install` fails, there is no code of ours running at that boundary.
There is nothing to return a refusal *from*. The only closed posture available
is `artifact` refusing to construct — and even that is escapable by a host that
catches the error and carries on. This is exactly what `ProtectionManifest`'s
`unpatchable` list already records, and `fail_closed` does not improve on it:
it makes the absence fatal at construction instead of advisory.

### f5. The telemetry emit inside `_emit_fail_closed` — regress has no floor

`_emit_fail_closed` wraps its own telemetry enqueue in `except: pass`. There is
no fail-closed available here, because failing closed on a failure to *report* a
fail-closed is unbounded regress. The verdict is still returned; only the
record of it can be lost. This is the same reasoning `_emit_scan_error` already
documents for its own emit.

### f6. `circuit_state` — an accessor, not a control decision

Excluded from `controls` deliberately. A host polls this property; raising out
of a property read is a worse surprise than a stale `"closed"`. The read that
*decides* something — `_circuit_is_blocking`, on the scan path — is closed
instead. `test_B7_circuit_state_property_never_raises_even_closed` pins the
exclusion so it stays a decision rather than becoming an oversight.

### f7. A wrong-typed input — the sensor CAN say what happened

`_coerce_scannable` returning `None` stays open in every group. A host passing
an `int` has a bug, not an attacker, and `input_status="not_scannable"` already
makes that bug visible. Refusing would convert every such host bug into a
production outage while telling the operator nothing new. It is also the one
case where fail-closed would be actively misleading: the `internal` group's
premise is that no reliable verdict could be produced, and here the sensor
knows exactly what happened.

### f8. Observability (class N) — implementable, and refused

Telemetry queues, reporters, log sinks, the trace-context resolver. These never
touch a verdict. A `fail_closed` that blocks production traffic because a
webhook is down is an availability bug with a security-sounding name. The
reviewers' phrase "the sensor fails open" covers these sites too; conceding
them would be wrong. They are not offered and `resolve()` has no group name
that reaches them.

---

## Failing-first proof

Both defects below were found DURING this work, by the two instruments the
shipping conditions required. Each is proved red against the pre-fix state with
its message, then green.

### 1. The `bounds` signal refused on SIZE, not on coverage

Sabotage: `_BOUND_SIGNAL_RULES` reverted to name `_OVERSIZED_INPUT_RULE`
instead of `_SCAN_INCOMPLETE_RULE` — the design as originally written.

```
$ PYTHONPATH=. python -m pytest tests/test_benign_longform.py::test_a_fully_read_long_document_is_NOT_refused -q
E   AssertionError: fail_closed=('bounds',) refused a document that was read COMPLETELY and scored nothing:
E       LF-thread_dump-150k (150,251 chars) rules=['LLM01_oversized_input']
E       LF-csv_export-150k (150,013 chars) rules=['LLM01_oversized_input']
E     That is a refusal on SIZE, which is not a bound fault. The signal in
E     _BOUND_SIGNAL_RULES has regressed to LLM01_oversized_input.
1 failed in 54.48s
```

Restored:

```
$ PYTHONPATH=. python -m pytest tests/test_benign_longform.py -q
7 passed in 85.08s
```

**Both directions, per the third proof obligation.** The new gate going red is
half of it; the other half is that the OLD gate stayed green on the same input.
`test_a_truncated_document_IS_refused` passes under both signals — refusing on
`LLM01_oversized_input` does catch every truncated document, because every
truncated document is also oversized. Nothing that only tested the truncated
case could have found this. The discriminating input is the one that is
oversized and NOT truncated, and no committed pool contained one.

### 2. `_extension_failed` deduplicated the refusal, not just the log

Sabotage: the original early-`return` dedup restored, so the fail-closed raise
placed after it fires on the first call only.

```
$ PYTHONPATH=. python -m pytest tests/test_fail_closed_sabotage.py::test_B1_gate_closed_refuses_EVERY_call_not_just_the_first -q
>       assert result.action == "blocked"
E       AssertionError: assert 'allowed' == 'blocked'
E         - blocked
E         + allowed
ERROR xaidr.sensor: extension 'broken-gate' raised in gate() ... THIS CONTROL IS
      INERT until the sensor is rebuilt — the scan continued on the open verdict.
      This message is logged once per extension per hook.
1 failed in 0.03s
```

Call 1 refuses; calls 2–5 return `allowed` from a sensor whose gate is dead —
the worst of both postures, and a single-call test passes straight over it.
Restored:

```
$ PYTHONPATH=. python -m pytest tests/test_fail_closed_sabotage.py -q
52 passed in 0.17s
```

### Regression gate on the default

```
$ PYTHONPATH=. python -m pytest <all tests except the two new pools> -q -p no:randomly
5895 passed, 15 skipped in 17.16s <!-- suite-count-ok: verbatim run output, evidence for this change, not a suite size -->
1446 passed, 49 skipped, 5 xfailed in 44.51s <!-- suite-count-ok: verbatim run output, evidence for this change, not a suite size -->
1221 passed, 73 skipped, 3 xfailed in 31.77s <!-- suite-count-ok: verbatim run output, evidence for this change, not a suite size -->
```

Run in three chunks; a full-suite run has crashed this machine before. The
three figures are the transcript of **that** run on macOS arm64 — the evidence
this change was regression-tested, not a statement of how large the suite is
now. They go stale the moment anything lands, and that is fine, because nothing
reads them as current. A count that IS meant to describe the suite today does
not belong in a doc at all; see the guard in
`tests/test_docs_no_published_suite_counts.py`, whose opt-out markers on the
three lines above are what this paragraph is the reason for.

Committed benign pools, before and after the change, at the default posture —
identical:

```
  asi.benign   n=146 blocked=1     benign_tc     n=190 blocked=0
  benign_a2a   n= 60 blocked=0     heldout.benign n=50 blocked=1
  benign_disc  n= 50 blocked=0     shell.benign  n= 78 blocked=0
  benign_dml   n= 50 blocked=0     shell.prose   n= 89 blocked=1
  shell.template n=12 blocked=0    shell.prose.tool n=89 blocked=0
  TOTAL n=814
```

---

## Milestone verification — from outside the process

A test that imports the module under test is not verification. This is the
package **installed as a wheel into a clean venv**, driven by a host script
with no `PYTHONPATH` and no test harness.

```
$ python -m venv extvenv && ./extvenv/bin/pip install /path/to/xaidr
$ ./extvenv/bin/python consumer.py
xaidr from: .../extvenv/lib/python3.12/site-packages/xaidr/__init__.py

1. default          -> allowed  cat=None rules=[]
2. controls closed  -> blocked  cat=fail_closed rules=['FAIL_CLOSED_CONTROL_FAULT'] halt=True
3. monitor+closed   -> flagged  cat=fail_closed  (must NOT be blocked)
4. approval_required-> approval_required requires_approval=True
5. artifact healthy -> constructed; degradations=[]
6. typo rejected    -> fail_closed: unknown group 'bonuds'. Did you mean 'bounds'?
7. tool refusal     -> str: [BLOCKED] Tool 'send_email' was NOT executed: the security sensor could not produce a reliable ...

ALL EXTERNAL CHECKS PASSED
```

Then the `artifact` group against a genuinely corrupt install — the installed
`all-l1-rules.json` overwritten with invalid JSON:

```
$ printf '{ this is not valid json' > extvenv/.../xaidr/rules/all-l1-rules.json
$ ./extvenv/bin/python - <<'PY'
A. import xaidr succeeded on a corrupt asset (contract preserved)
B. default constructs; degradations =
      {'kind': 'asset', 'detail': 'all-l1-rules.json: failed to load (JSONDecodeError); using empty ruleset'}
   and scans DEGRADED: flagged 0.65 ['direct_override_safety', 'exfiltrate_secret']
C. artifact closed REFUSED TO CONSTRUCT:
      fail_closed=('artifact',): the sensor was NOT built because 1 rule asset(s) did not load as authored:
        - all-l1-rules.json: failed to load (JSONDecodeError); using empty ruleset
D. no verdict was produced; the failure is at construction, not on traffic
```

Three things that check establishes and no in-tree test could:

* **`import xaidr` still succeeds on a corrupt asset.** The contract
  `l1._load_and_compile` has always kept is preserved. §f1's split between the
  fault point and the fail-closed point is real, not a comment.
* **The degradation is now visible without opting in.** `Sensor.degradations`
  names the asset on a default sensor. Before this change the only trace was a
  `print` to stdout.
* **It costs a verdict, measurably.** The same obvious injection scores
  `blocked 0.88` on a healthy install and `flagged 0.65` on the corrupt one.
  That is what `artifact` exists to stop a deployment from running into
  unknowingly — and it stops it at construction, with the file named, not by
  refusing traffic.

`/milestone-verify` is referenced by the operating notes but is not installed
in this environment (`~/.claude/commands/` has no such command), so the checks
above were run directly.

### Still unverified, and what would settle it

* **The A2A walk bounds at depth 6–8.** `benign_a2a/` tops out at depth 4
  against a bound of 8. The group is shippable because nothing honest in that
  pool comes near the bound, but the FP cost of *moving* the bound is
  unmeasured. Settled by extending that pool, not by anything here.
* **Four of nine `bounds` sites remain blind** (C9, C11, C12, C13) — see the
  §e table. Each needs an input class no committed pool contains.
