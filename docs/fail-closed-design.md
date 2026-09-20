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

### The headline

**Of the four groups, the committed benign pools can measure exactly one, and
within that one they can measure three of its thirteen sites.**

| Group | benign items that would block | status of that number |
|---|---:|---|
| G1 `artifact` | **0** | true *by construction* — G1 is not a traffic verdict |
| G2 `controls` | **0** | **BLIND** — every site is unreachable in the harness |
| G3 `bounds` | **1 / 814** | partially measured; 5 of 13 sites blind |
| G4 `internal` | **0** | **BLIND** — needs fault injection, not a corpus |

### Why G2's zero is not a number

`corpus_diff.py:92` builds `Sensor(agent_id=..., enforcement_mode="block",
reporter=_NullReporter())`. Measured:

```
circuit_breaker = None   -> breaker counter faults unreachable   (B7)
extensions      = ()     -> every extension hook unreachable     (B1-B5)
escalators      = ()     -> escalation timeout unreachable       (B6)
enable_nano     = False  -> nano load + inference unreachable    (A8)
policy_file     = None   -> ./xaidr-policy.yaml present? False
                            the detection-only fallback is the ONLY
                            state the pools ever observe          (A6)
autopatch       = never called by any pool                        (B8/B9)
```

Every G2 site is off before the first item is scanned. This is the same shape
`benign_a2a/README.md` already documents for the structural validator — "a gate
that passes on a population the change cannot touch reads as coverage while
performing none." **Reporting "G2 costs 0 false positives" from this harness
would be the eighth instance.**

### Why G4's zero is not a number

D-sites fire only when the sensor's own code raises. A corpus of well-formed
inputs cannot contain "a scanner bug". Measuring G4 needs per-site sabotage —
which the repo already has an instrument for
(`tests/test_operational_resilience.py:265` `_capture_fail_open`, and the
per-site fail-open sabotage `docs/releasing.md:37` names) — and that instrument
is not a benign pool. G4's real cost is `P(internal fault on honest traffic)`,
which no corpus can estimate.

### G3, site by site — what is measured and what is not

| Site | Pool that could reach it | Measured | Verdict on the number |
|---|---|---|---|
| C7/C8 SQL bounds & predicate | `benign_dml` (50), `benign_tc` (3) | max **134** chars vs `MAX_SQL_CHARS=20_000`; max **3** statements vs `MAX_STATEMENTS=32`; **0 / 50** produce `unknown` or `unparsed` | **REAL.** The pool was built for this class. Matches the figure already recorded in `impact-classes.json` for `sql.unbounded_mutation`. |
| C1/C2/C3 A2A walk | `benign_a2a` (60) — the only pool with dict A2A bodies | max depth **4** vs `_MAX_NEST_DEPTH=8`; max nodes **27** vs `_MAX_NEST_NODES=64`; depth histogram `{0:1, 1:1, 2:37, 3:19, 4:2}` | **REAL but weak.** 0 benign items would block. The pool sits at half the bound and has nothing in the 5–8 band, so it shows the bound is clear of honest A2A — it cannot price *lowering* the bound. |
| C10 command parse degraded | `shell.benign` (78), `asi.benign` | **1 / 814** — `ASI05-B03`, `print(sum(range(10)))`, a Python payload shell-tokenized. All 78 `shell.benign` commands parse clean; `shlex` never fell back. | **REAL.** This is G3's entire measured cost: **1 benign item**. |
| C4/C5 L1 over-length & budget | none | longest benign item **anywhere** is 3 241 chars vs `L1_MAX_SCAN_CHARS = 100_000` — **31× short** | **BLIND.** No committed pool contains a document-sized input. "0 benign items block on the over-length path" is not a measurement, it is absent test data — and C4 is the site with the largest plausible FP cost in the whole design. |
| C9 argument-tree walk | `benign_toolcalls` | max **10** string values in any benign arg tree vs `_MAX_CANDIDATE_VALUES = 64` | **BLIND.** 6× short of the bound; the `RecursionError` arm needs a ~1000-deep tree no pool contains. |
| C11 URL parse | `benign_tc` (48), `benign_disc` (5) | 0 faults; no item near `MAX_URL_CHARS = 4_000` | **BLIND for the cap**, real for the fault arm. |
| C12 deep-JSON `RecursionError` | `benign_a2a` | 0; max body 3 241 chars, depth 4 | **BLIND.** |
| C13 unrenderable arguments | `benign_toolcalls` | 0; every arg tree is JSON by construction (the pools are `.jsonl`) | **BLIND** — the file format forbids the input class. |
| C6 pathological pattern | none | 0 | **BLIND**, and moot: already closed at 0.65. |
| E2 `not_scannable` | none | every scanned pool value is `str` (665) or `dict` (60); `_coerce_scannable` returns `None` only for neither | **BLIND** — the pool schemas forbid the input class. |

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

## What would end the blindness

Per group, the corpus work the measurement needs. None of it is the feature.

* **G2** — not a corpus of inputs but a corpus of *faults*: one benign item run
  through a sensor carrying an extension that raises in each hook, an escalator
  that times out, a breaker whose counter throws. The variable is the fault,
  not the input, so it is small.
* **G3/C4** — a benign large-document pool. Nothing committed exceeds 3 241
  characters against a 100 000 cap. This is the single largest gap in the
  measurement and the site most likely to produce a real false positive.
* **G3/C1-C3** — `benign_a2a` items at depth 6–8, not 2–4. The present pool
  proves the bound is clear; it cannot price the bound.
* **G4** — per-site sabotage, extending `_capture_fail_open`. Not a corpus.

## Still open — deliberately not answered here

§c (what a refusal returns, per framework return contract — the LangGraph
`ToolMessage` lesson at `autopatch/frameworks.py:246-320`, and whether an
approval-gated deployment wants `approval_required` rather than `blocked`),
§d (the release note for keeping the default open), and §f (sites where
fail-closed is not implementable) follow once the grouping above is agreed.
