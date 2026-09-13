# Enterprise seams for open `xaidr` — design against `864243e`

**Status:** ALL THIRTEEN SEAMS BUILT. S7 (PR 1); S1 + S5 + S6 (PR 2); S2 (PR 3, completed in PR 5); S3 (PR 4); S9 + S10 + S11 (PR 5); S12 flag-gated (PR 6); S4 + S8 + S13 (PR 7).

**Two hooks on `SensorExtension` are DECLARED BUT NEVER CALLED**, found by grepping every hook name against the tree at the close of PR 7:

| hook | status |
|---|---|
| `outbound_headers(dest)` | S12 shipped the consolidation and the flag; the extension merge with the collision rule is still owed. Known and recorded when S12 landed. **Tracked: [#14](https://github.com/delphisecurity/xaidr/issues/14)** |
| `enforcement_policy()` | **Not previously flagged.** S7 shipped mode registration through `resolve()` / `_POLICIES`, which takes a name or an already-resolved policy object. The hook was declared with the rest of the surface in S1 and no call site was ever added. **Tracked: [#13](https://github.com/delphisecurity/xaidr/issues/13)** |

This is the `Action.ESCALATED` failure class from S3 restated for hooks: a declared surface with no consumer is not inert, it is a promise the object's docstring makes and the code does not keep. An enterprise package subclassing `SensorExtension` and overriding `enforcement_policy` today gets silence, with nothing raising and nothing logged. Either wire it or delete it; leaving it declared is the one option that misleads. Base: `delphisecurity/xaidr` main at `864243e` (release 1.11.0); the seam line numbers in §2 are on that commit and have since shifted — read them as "which function", not "which line". PR #3 (ASI/LPCI rules) shifts `local.py` by +34 lines and touches no seam site.
**Companion:** `docs/enterprise-overlay-spec.md` (the bucket classification, currently sitting in `~/delphi-sentinel/docs/`, to be moved to the SDK repo). This document replaces its §5 hook table.
**Goal:** paid = pinned open `xaidr` + an enterprise package. Every behaviour paid has today that open lacks must plug into open through a public, tested, validated-at-construction seam, so that the next open release cannot silently break the enterprise package and the next enterprise feature cannot fork a shared file.

## 0. Non-negotiables

1. **No behaviour change with no extension registered.** Every seam, unregistered, must leave the **456-row** corpus oracle byte-identical (verdict, score, rule set) and the full suite count unchanged except for the seam's own new tests. (`tests/fixtures/shell_corpus.json`: 277 attacks + 78 benign + 89 benign prose + 12 benign templates. An earlier draft of this line said 545, which was never true at any commit — it is 456 at `864243e` and at `2e29182`. A denominator asserted from memory is the same failure class as a coverage claim asserted from memory, so the gate now asserts its own row count: `test_seam_zero_movement.py::test_the_corpus_is_the_size_the_design_doc_claims`.)
2. **Validate at construction, loudly.** A seam handed something it does not understand raises `ValueError` naming the received type, matching `circuit_breaker=` (`sensor.py:377`) and `enforcement_mode` (`:265`). A silently ignored bad extension is the ADV-2 failure class.
3. **Fail-safe at call time, but not silently.** A fault inside an extension hook is caught, the scan proceeds on the open verdict, and the fault is logged at ERROR **once per extension per hook per sensor** with a message that says the control is inert, following `_breaker_counter_failed` (`sensor.py:542`), not the older swallow-and-forget in `_fire_on_trip`.
4. **`Optional[X]` return means proceed.** The convention already in `autopatch/core.py:113` and the CrewAI hooks. A hook that returns `None` has declined; a value short-circuits.
5. **Ordering is pinned by tests, not comments.** The three existing invariant tests (`test_circuit_breaker.py:201`, `test_approval_required.py:139`, `:~131`) stay green, and each new seam that touches the verdict path gets one more.
6. **No new dependencies in open.** Seams are plain Python. The enterprise package brings its own.
7. **Content by hash.** Nothing in a seam gives an extension the raw prompt beyond what the hook already receives as the scan input. The enterprise reporter's `capture_content` (default `False`) is enterprise config, not an open seam.

## 1. The extension object

One object, not fifteen callables. Precedent: `Reporter` is a Protocol; `CircuitBreaker` is a concrete object validated by `isinstance`. We follow the second, because a Protocol with optional methods cannot be runtime-checked and rule 2 requires a check.

```python
# xaidr/extensions.py  (new, open)
class SensorExtension:
    """Base class. Every hook is a no-op; subclasses override what they need.
    Instances are attached with Sensor(extensions=[...]) and validated by isinstance."""
    name: str = "extension"          # appears in logs and the manifest

    def on_attach(self, sensor) -> None: ...
    def policy_conditions(self) -> Mapping[str, ConditionEvaluator]: return {}
    def escalators(self) -> Sequence[Escalator]: return ()
    def before_scan(self, req: ScanRequest) -> Optional[ScanResult]: return None
    def gate(self, req: ScanRequest) -> Optional[ScanResult]: return None
    def transform_verdict(self, req: ScanRequest, result: ScanResult) -> ScanResult: return result
    def enforcement_policy(self) -> Optional[EnforcementPolicy]: return None
    def on_response(self, resp: ResponseView) -> None: ...
    def subject_trust(self, agent_id: str) -> Optional[float]: return None
    def destination_policy(self, dest: DestinationView) -> Optional[ScanResult]: return None
    def blocked_urls(self) -> Optional[Sequence[str]]: return None
    def outbound_headers(self, dest: DestinationView) -> Mapping[str, str]: return {}
    def on_tools_declared(self, tools: Sequence[ToolView]) -> None: ...
```

`Sensor(extensions: Sequence[SensorExtension] = ())`. Order is significant and is the order given. The manifest (`ProtectionManifest`) lists attached extensions by name so an operator can see what is installed.

`ScanRequest`, `ResponseView`, `DestinationView`, `ToolView` are small frozen dataclasses in the same module. They are the public contract; they carry ids, hashes, direction, provider, host, tool name, argument hash, principal/agent/trace context. They do not carry the raw prompt except in `ScanRequest.text`, which the scan already has.

## 2. The seams

Site line numbers are on `864243e`. `local.py` sites are +34 after PR #3.

### S1 · attach — `DelphiSensor.__init__`, BUILT

Validate every item is a `SensorExtension` (raise otherwise), store the tuple, call `on_attach(self)` in order. `on_attach` is where the enterprise package registers its `BrainReporter` if `reporter=` was not given, reads the deployment key, and performs the loud config check (missing/malformed key with enterprise mode requested → raise; see backlog "Enterprise package key handling"). A fault in `on_attach` is a construction failure, not a runtime one: it raises.

Inherits fresh code: `self._breaker_faults` (`:372-375`) is in the same function. Insert after the breaker wiring at `:386` so extensions see a fully built sensor.

### S2 · policy conditions — `authz/policy.py` + `local_policy.py` (was H2 + H10), BUILT

The spec's two sites are one seam. Today `_CONDITION_FIELDS` is a module-level frozenset consulted inside `parse_action_policy`, `trust_below` is rejected at `:161` in both placements, and `_reject_unknown_keys` (`:82`, applied `:175/:177`) would reject it a second time with a misleading did-you-mean.

Design: `parse_action_policy(doc, *, extra_conditions: Mapping[str, ConditionEvaluator] = {})`. `load_policy` gains the same kwarg and forwards it. `DelphiSensor.__init__` collects `policy_conditions()` from every extension, merges (duplicate key across extensions → construction error), and passes the merged map. Inside the parser, the valid-key set for the unknown-key validator is `_CONDITION_FIELDS | extra.keys()`, and the `:161` rejection is skipped for any key in `extra`. The evaluator is called at evaluation time with the request context and the extension owns its semantics (`trust_below` reads `subject_trust`, S9).

**S2 was INCOMPLETE as first merged, and the gap was found building S9.** `extra_conditions` reached `parse_action_policy` and stopped there — `evaluate()` never received it and `_rule_matches` handled only the two built-in names, so a registered condition parsed cleanly and was DROPPED at evaluation. That does not merely fail to fire, it **widens** the rule: a condition is written to NARROW a `match:` block, so dropping it makes the rule fire on everything the match alone selects. Reproduced on the merged tree: `geo_outside` never evaluated, every `wire_transfer` blocked instead of the non-EU ones. The evaluators now ride WITH the parsed policy (`condition_evaluators`), and both failure directions fail CLOSED — an unregistered evaluator at eval time, and an evaluator that raises. Built-in names keep built-in semantics: registering `trust_below` means "I supply the score" (S9), not "I replace the comparison".

Open's stricter behaviour is unchanged when `extra` is empty: `trust_below` stays rejected, pinned by the existing test. The paid control test (`test_trust_below_still_supported_here`) moves to the enterprise package unchanged.

**Census correction — the design above named two entry points; the tree has three.** `parse_action_policy` is reached from `local_policy.load_policy` (a policy FILE) *and* from `local_policy.set_policy_dict`, which backs the public `Sensor.set_policy()` runtime API. `load_policy` also does not live in `authz/policy.py` at all. Wiring only what this section named would have left `Sensor(extensions=[...]).set_policy({...})` rejecting the extension's own condition — a live gap in the shipped API, invisible to any test that only loads policies from disk. **This is the S7 lesson repeating for the third time: enumerate sites from the tree, never from a document's line list.** All three now take `extra_conditions`, and `test_set_policy_accepts_an_extension_condition` is the test that would have caught the omission.

**Ordering: S1 had to be split.** The policy is parsed inside `__init__` (`sensor.py`, at the `load_policy` call), but S1's attach block ran at the END of the constructor, so `policy_conditions()` had not been collected when the parser ran. Validation and condition-collection are now "part 1 of 2", hoisted above the policy load; `on_attach` stays last and still receives a fully built sensor. Both halves of S1's contract survive, and the split is commented at both sites.

**The exemption is keyed on the KEY, not on "an extension is present".** `if "trust_below" not in _extra and (...)` — writing it as `if not _extra and (...)` passes every other test in the file and lets `trust_below` through whenever *any* unrelated condition is registered. `test_trust_below_still_rejected_when_a_DIFFERENT_condition_is_registered` is the discriminating case and was proven red against exactly that mis-implementation. (Only its `conditions:` parametrisation discriminates: under `match:`, `trust_below` is caught a second time by the `_MATCH_FIELDS` unknown-key validator.)

Duplicate condition names across two extensions raise at construction naming both extensions and the key, rather than last-write-wins: two packages both believing they own a condition, one silently inert, is the ADV-2 shape.

Measured: corpus oracle byte-identical with no extensions (456 rows, `80f31ff0…`); full suite 7931 → 7951, which is exactly the 20 new tests; skips unchanged at 137.

### S3 · escalation chain — `scanner/local.py` (was H3 + H8), BUILT

Open is three-state with no escalation. Add, after the local verdict is computed and only in the flag band:

```python
for esc in self._escalators:
    r = esc.scan(req, local_result)   # Optional[ScanResult]
    if r is not None: result = r; break
```

`Escalator` is a small base class: `scan()`, `health() -> HealthReport`, `timeout_ms`. `LocalScanner.__init__` gains `escalators: Sequence[Escalator] = ()`; the sensor collects them from `extensions[].escalators()` in order and passes them (construction site `sensor.py:300`; `:313`'s `_scanner_mode = "local"` literal becomes derived from whether any escalator is present).

Rules that carry over from paid unchanged: escalate only in the flag band; `_flag_band_cap(escalate_threshold)` so documentary prose does not cost a round-trip per input; a link that times out or errors is skipped and the event records `escalation: skipped, reason: <link>_unreachable` (never silent); `health()` is called once at construction and reported in the manifest.

The enterprise package registers exactly one escalator: the Brain (`scanner/remote.py`). Per the Sept 6 decision the nano and CPU-L4 sidecar sits beside the Brain and is the Brain's concern; the SDK never addresses it. In-process nano stays the open `[nano]` extra, default off, in both.

Note for the ledger thread: with `ext_authz` on a gateway egress route, escalation inherits the 200 ms PEP timeout. Any scan on that path must stay in the fast band or the timeout must be per-route.

**Census corrections — five, and one of them was a latent bug.** As with S2, the doc's line numbers were the least of it:

* `_flag_band_cap(escalate_threshold)` does not exist. The tree has **`_FLAG_BAND_CAP(block_threshold, flag_threshold)`** (`scanner/local.py:330`), and **`escalate_threshold` appears nowhere in the tree**. There is no separate escalation threshold to cap against; the cap is the existing flag-band clamp.
* **Nothing recorded that a cap had fired.** Both cap sites were bare `score = min(score, _FLAG_BAND_CAP(...))`. "Do not escalate documentary prose" needed a new `flag_band_capped` flag, deliberately NOT named `capped` — that name is already taken in `scan()` for the size-capped TEXT, and the two meanings are unrelated.
* `scan()` has **one** return, not an insertion point at `:684`. Escalation goes immediately before it, after `verdict`/`action` are decided.
* **"reported in the manifest" has no home.** `ProtectionManifest` is built only by `xaidr.protect()`, never for a plain `Sensor(...)`. `health()` failures are logged at ERROR at construction instead, following the log-once discipline S1 set for extension code. An unhealthy link is **reported, not disabled** — a backend down at boot may be up by the first scan, and refusing to construct would turn a transient outage into an outage of the host. (Contrast nano, which *does* raise: a hash-mismatched artifact is permanent, local and fixable.)
* **`Action.ESCALATED` already existed** (`types.py:70`), produced by nothing and referenced only in one test's tolerance list. S3 is the first code that can emit it — and `_ACTION_SEVERITY` (S6, `sensor.py`) had no entry for it, while `_ACTION_SEVERITY[before.action]` is an **unguarded** lookup. Reproduced on clean main before the fix:

  ```
  KeyError: 'escalated' <-- unguarded _ACTION_SEVERITY[before.action]
  ```

  In a real scan that KeyError reaches the outer fail-open handler, so an escalated verdict plus any transforming extension would have become a silent `allowed`. S3 adds the map entry (`"escalated": 1` — a second *opinion*, not a halt) and a test.

**S1 is now split three ways in `__init__`,** because three things consume extensions at construction and two of them are built early: the escalation chain (into `LocalScanner`), the policy condition names (into `parse_action_policy`), and `on_attach` last. Hooks that CONTRIBUTE run early; the hook that OBSERVES runs on a finished object.

**Timeouts use a daemon thread, not `concurrent.futures`.** The executor joins its workers at interpreter exit, so a genuinely hung link would hang the HOST's shutdown — trading a slow scan for an unkillable process. An abandoned daemon thread leaks a thread until the process ends, which is the lesser failure and the visible one.

Measured: corpus oracle byte-identical with no escalators (456 rows, `80f31ff0…`); full suite 7997 → 8020, exactly the 23 new tests; skips 137 and xfails 3 unchanged.

### S4 · before_scan — inside `_run_gates` (was H4), BUILT

Called with the built `ScanRequest`, returning `Optional[ScanResult]`; a value short-circuits everything **including telemetry**, so it is reserved for "this request is not ours" cases. That is a stronger short-circuit than S5's gate, which still emits an event — the asymmetry is deliberate and is pinned by a pair of tests, because a control that halts traffic while leaving no audit record is not a control.

**ORDERING CORRECTION — the doc was wrong and section 3's table is corrected with it.** This section and the table both said "before the gate (S5)". S5's chain BEGINS with the circuit breaker, so taken literally an extension hook would outrank an operator-configured halt: with the breaker open, `before_scan` would answer a call the breaker exists to stop. Nothing else in this seam set may widen an open control (S6 may only soften, S10 may only tighten, an escalator cannot un-block), and this is the same rule. **Actual order: circuit gate → before_scan → extension gates.** `test_an_open_circuit_still_wins` pins it, and a sabotage that hoists before_scan above the circuit fails it.

**THREE hook sites, not four.** The doc named four entry points; `scan_output` DELEGATES to `scan(direction="output")` in this tree and is not independent. Hooking both would fire `before_scan` twice for one call — double traffic to any extension counting requests. `test_scan_output_does_not_fire_the_hook_twice` is the guard.

### S5 · gate chain — three scan entry points (was H5), BUILT

Open already short-circuits at these three sites via `_circuit_is_blocking()`. Generalise: `self._gates = [self._circuit_gate] + [ext.gate for ext in extensions]`, walked in order; the first non-`None` result is emitted through the existing `_emit_circuit_open_verdict` path generalised to `_emit_gate_verdict(result, gate_name)`. Position is unchanged: **before** telemetry enqueue, before `_breaker_observe`, before `_apply_mode`. That is the invariant "quarantine gates before the mode transform", and it holds by construction because a gated verdict never reaches `_apply_mode`.

`tests/test_inert_stubs_audit.py:280-294` asserts no quarantine exists in open. It stays true: open has no quarantine gate; the enterprise package's gate is the quarantine. The test is reworded to assert "no gate other than the circuit gate is registered on a bare sensor."

### S6 · verdict transform — `DelphiSensor._apply_mode` (was H6), BUILT

After the open downgrade logic, `for ext: result = ext.transform_verdict(req, result)`. This is the seam for paid's fleet-driven mode (Brain says this deployment is `watch`), and it runs **after** enqueue (`:911`) and `_breaker_observe` (`:918`), so telemetry and the breaker keep the true verdict. A transform may only move a verdict toward `allowed`/`flagged`; a transform that returns a stricter action than it received raises at call time (that is what the gate is for, and it would bypass the breaker).

New test: an extension that downgrades every verdict; assert telemetry still carries the original action and `circuit_state` still opens (the same shape as `test_circuit_breaker.py:201`).

Built in `xaidr/extensions.py` (`SensorExtension` plus the four frozen views) and wired at the three scan entry points. Notes from building it, each of which cost a test:

* **The gate chain runs before `_breaker_observe`, so a gate suppresses breaker counting entirely.** That is correct — a quarantined call never reached detection, so there is no verdict to count — but it means a test cannot both install a blanket gate and trip the breaker. The circuit-precedence test arms its gate only after the breaker has tripped.
* **A blocked→flagged transform is INVISIBLE to the breaker**, because `_breaker_observe` already counts a high-scoring `flagged` as a true block (that is what lets the breaker trip in monitor mode). The ordering test therefore has to downgrade to `allowed` to discriminate. Written the obvious way it passed against S6 deliberately mis-ordered — a decorative test, caught only by running the sabotage.
* **The strengthening check must bypass the fail-open handler.** First cut raised `_VerdictStrengthenedError` inside the scan body, where the outer `except Exception` turned it into `allowed` + `SCAN_FAILED_OPEN` — a mis-written enterprise control silently becoming "allowed". It is now re-raised alongside `DelphiBlockedError` at all four sites.
* **The `ScanRequest` is built lazily.** The tool boundary hashes its arguments to fill `arguments_hash`, so passing the fields eagerly would have made every no-extension tool call pay for a view nobody reads. The three call sites pass a thunk.

Measured, no extensions vs one no-op extension: median 0.320 ms → 0.324 ms, p95 0.348 ms → 0.347 ms (budget 3 ms).

### S7 · enforcement policy object (was H7) — seven sites, BUILT (`876dbf1` on main)

`enforcement_mode` was compared as a string literal in six places plus one membership test: `_circuit_is_blocking`, `_apply_mode`, three sites in the tool-argument hard-category path (`_scan_tool_call_impl` region), `LocalScanner.scan` (which collapses block→flagged inside the scanner before the sensor sees it), and the constructor's `not in ("monitor", "block")`. The recon listed four; the grep found seven. **Census lesson: enumerate sites from the tree, never from a document's line list.**

Built: `xaidr/enforcement.py` with `EnforcementPolicy` (`name`, `enforces()`, `downgrade(action)`), instances `MONITOR` and `BLOCK`, and `resolve()` mapping the two strings to objects and raising on anything else. All six comparison sites asked one question (does a halting verdict halt) and map to `enforces()`; `_apply_mode` maps to `downgrade()`. Sensor and `LocalScanner` accept a name or a resolved policy; a bare `LocalScanner` with an unimplemented mode now raises rather than silently behaving as monitor. An extension may register further names through `resolve()` (paid's `watch`, or a Brain-driven policy), so `Sensor(enforcement_mode="watch")` raises with no extension and works with the enterprise one.

Two tripwires: (1) `git grep` for `enforcement_mode ==` / `!=` in `xaidr/` must be empty, both operand orders; (2) the literal two-mode tuple must not reappear. **Tripwire lesson: `git grep -E` is POSIX ERE, so `\s` is a literal `s`; use `[[:space:]]`, and pair every grep tripwire with a harness test that greps for a construct known to exist, so a dialect change fails loudly.** Non-vacuity: reverting the sources fails 8 tests (both tripwires plus six wiring tests).

### S8 · on_response — `ProtectedHttpClient._scan_response` (`sensor.py:3631`, was H9), BUILT

After the open output scan — **after the block raise**, so a response the sensor has already decided to block never reaches a hook. Every extension receives a `ResponseView` carrying provider, host, status, content-type and the parsed JSON body.

**Everything is REUSED, not recomputed.** `rbody` is already parsed at the top of `_scan_response` for the A2A id tracker, and `_extract_provider` / `_extract_host` are the same helpers the output scan and S10 already use. A second provider-detection path here would be free to disagree with the first about what host this is — exactly the drift S12 removed from the egress headers.

**CENSUS CORRECTION: there is no `stream=` skip in this tree.** The claim that "the egress patch already skips `stream=True`" is false — grepping `xaidr/sensor.py` for stream handling returns only the word "downstream". No streaming path exists to skip, and the "SSE-with-no-stream-kwarg case is a separate bug, filed" note describes machinery that was never built. S8 therefore inherits whatever the egress patch does today, which is nothing special for streams; if streaming support lands, S8's position must be re-checked rather than assumed.

Observation only: the hook returns None and cannot change the response. This is where the token-usage extractor for the ledger lands later.

### S9 · subject trust — `evaluate_policy` callers (was H11), BUILT

**Census correction:** `build_request` has exactly ONE caller and it is `local_policy.py`, inside `evaluate_policy` — the sensor never calls `build_request`. The two hardcoded `trust=None` sites are calls to `evaluate_policy` (`sensor.py`, tool path and HTTP destination path). The count of two was right; the function and the file were both wrong. The inert-stubs assertion is at `:349`, not `:304`.

`evaluate_policy(..., trust=...)` already takes a trust parameter and both callers hardcode `None`. Replace with `self._subject_trust(agent_id)`, which asks each extension in order and returns the first non-`None`. `tests/test_inert_stubs_audit.py:304` asserts `not hasattr(s, "_trust_score")`; reworded to assert a bare sensor's `_subject_trust()` returns `None` and no attribute stores a score.

### S10 · destination policy — `ProtectedHttpClient._check_destination` (was H12), BUILT

Before the operator blocklist check (`:2434`), each extension's `destination_policy(DestinationView)` may return a block result. **Census correction:** `dest_id` is NOT computed once up front — on the merged tree it is computed INSIDE the blocklist branch, only after a block has already fired. The view therefore computes it lazily and only when an extension is attached, so a bare sensor does not start paying for a parse it never needed. It carries the host only, never the URL or query.

**This seam makes #5's forward-looking sabotage live.** PR 2 added `except (DelphiBlockedError, _VerdictStrengthenedError)` to `_check_destination` and reported honestly that the clause was UNREACHABLE, because nothing on that path could raise it. S10 puts extension code inside that function for the first time; the contract errors now share an `_ExtensionContractError` base (see §4) and the clause is what stops a mis-written `destination_policy` becoming a silently permitted destination. The enterprise AGT URL policy plugs here. The three paid `print`s that leaked full URLs do not come across; the open host-only emission is the only path.

### S11 · blocked URLs provider — one reader, two mutators (was H13), BUILT

The reader at `:2435` holds `self._sensor._blocked_urls`, and `unblock_urls` rebinds the list at `:1692`, so any provider that caches a reference goes stale. Design: `_effective_blocked_urls()` computed at read time as `self._blocked_urls + [u for ext in extensions for u in (ext.blocked_urls() or ())]`, called at `:2435` on every check. No refresh hook is needed; a provider that wants freshness returns a fresh sequence each call and rate-limits itself. Test: register a provider whose list changes between two calls and assert the second call sees the change. Also tested: `unblock_urls` composed with a provider — the operator's removal takes effect while the extension's contribution survives the rebind, which is exactly the staleness a cached reference produces. An operator cannot `unblock_urls` an extension's entry; that list is the extension's, and letting the operator delete from it would make the enterprise control removable by the thing it constrains.

### S12 · outbound headers — five egress verbs (was H14), BUILT (flag-gated)

One `_egress_headers(dest, headers, *, source_agent) -> dict` used by all five verbs: `post` (`sensor.py:3424`), `put` (`:3433`), `patch` (`:3442`), `get` (`:3451`), `delete` (`:3460`). Before this seam the three body verbs wrote `X-Delphi-Source-Agent` and GET/DELETE wrote no header at all.

**Gated by `Sensor(emit_provenance_headers=False)`, default OFF.** The flag is what makes this seam SATISFY non-negotiable #1 rather than override it. An earlier draft of this section framed the `inject_context` wiring as "an open behaviour change in its own right" — that framing is withdrawn, because with a default-off flag the default behaviour does not change at all.

* **Flag off:** byte-identical to the tree before this seam. Body verbs send exactly `X-Delphi-Source-Agent`; GET and DELETE send nothing. The asymmetry is preserved deliberately — GET/DELETE starting to announce the agent id to hosts that never received it is a DISCLOSURE change, and consolidating call sites is not a licence to make one.
* **Flag on:** every verb carries `X-Delphi-Source-Agent` plus the four headers `provenance_chain.inject_context` (`provenance_chain.py:387`) writes — `traceparent`, `x-openA2A-correlation`, `x-openA2A-chain`, `x-openA2A-tiers`. GET and DELETE are included on purpose: a deployer who asked for the chain to be visible should not find a GET-shaped hole in it.

**The disclosure is the reason for the default.** With the flag on, every destination a protected client talks to receives this agent's id, a correlation id and the delegation chain. That is not the SDK's call to make on a deployer's behalf, so it is opt-in — the same reasoning as `enable_nano` refusing to fetch a 130 MB artifact as a side effect of construction.

**The corpus oracle is blind to this seam**, and that is the interesting part. It hashes `scan()` verdicts over the committed corpus; it makes no HTTP request and inspects no header, so S12 could change what every outbound call discloses and the oracle would stay byte-identical. `tests/test_egress_headers.py` is the real zero-movement gate here, and it says so in its own docstring. A seam whose gate cannot see it needs a new gate, not a green run from the old one.

The `inject_context` claim in the earlier draft was verified rather than assumed: nothing in `xaidr/` called it. Only `__init__.py` (the export), four tests, and the user-facing docs did. The "writer exists, unwired" gap is now closed on the open side whenever the flag is on.

**Still design, NOT built here:** merging `ext.outbound_headers(dest)` from each extension, with the collision rule (extensions may add headers, never remove or overwrite an open one). The helper is the seam that will host it; this PR wired the consolidation and the flag only.

### S13 · tools declared — `Sensor.protect_tools` (`sensor.py:2455`, return at `:2860`; was H15), BUILT

After the wrapping loop, `ext.on_tools_declared(tools)` is called ONCE with the accumulated `ToolView`s — not once per tool. An extension registering an inventory wants the set; per-tool callbacks arrive as fragments it has to reassemble. An EMPTY tool list still reports an empty inventory, because "this agent exposes nothing" is a fact a consumer needs and is different from never having been told.

Views are built from what the loop already holds: `tools` are the caller's original objects, and `description` / `args_schema` are read off them with `getattr`. No new introspection machinery — inventing a second way to read a tool here is what would later disagree with the first.

**Hashed, per non-negotiable #7.** A description is author-written prose and a schema can carry field names from a private domain model; drift detection needs to know THAT they changed, not what they say. `None` means ABSENT rather than empty: if a deleted description hashed like an empty string, a removal would read as a no-op. `_hash_tool_attr` never raises, so a tool whose attribute access has side effects cannot break `protect_tools`.

The doc previously cited `:1956`; the real def is `:2455` and the return `:2860`.

### Eliminated: telemetry hook

Paid's hard-wired flush is replaced by `BrainReporter(Reporter)` through the existing `reporter=` kwarg (`sensor.py:254`, Protocol at `reporters.py:67`). Signed batches, `capture_content=False` default, `contentCaptured` flag on every event so the Brain's `:1329` path can record "attribution unavailable, content capture off" instead of returning zero rows.

## 3. Ordering, in one place

Per entry point, after S7's policy object is in place:

```
build ScanRequest
S5a circuit gate           (an operator halt; NOTHING below may override it)
S4  before_scan            (may short-circuit; NO telemetry, unlike a gate)
S5b extension gate chain   (a gated verdict skips everything below, but DOES emit)
local scan → S3 escalators (flag band only)
telemetry enqueue          (true verdict)              ← unchanged, :911/:1125/:1654
_breaker_observe           (true verdict)              ← unchanged, :918/:1131/:1661
_apply_mode                (open downgrade, then S6)   ← :919/:1132/:1662
return
```

Corrected for S4: the circuit gate is split out and runs FIRST. The earlier table put S4 ahead of the whole chain, which would have let an extension answer a call an open breaker had halted. Invariants pinned by tests: (a) a gated verdict never reaches enqueue; (b) enqueue and observe see the pre-S6 verdict; (c) S6 cannot strengthen; (d) S3 runs before enqueue so the escalated verdict is what telemetry records.

## 4. Fault handling contract

Per extension per hook per sensor: first fault logs ERROR with extension name, hook name, our own module:lineno, and the sentence "this control is inert until the sensor is rebuilt"; subsequent faults are counted, not logged. The set is `sensor._extension_faults` (keyed by extension name + hook), reported through `_extension_failed`. **There is no `manifest.faults`** — `ProtectionManifest` is built only by `xaidr.protect()`, never for a plain `Sensor(...)`, so an earlier draft's claim that it exposes the set was never true of this tree. Exception: `on_attach` raises (construction), and S6 strengthening raises (contract violation, not environment).

Contract violations share a base, `_ExtensionContractError`, and every scan entry point re-raises it alongside `DelphiBlockedError` rather than letting the fail-open handler turn it into `allowed`. The distinction the base draws is the one the whole extension system rests on: an ENVIRONMENT fault (a backend is down) is caught, logged once, and the scan proceeds on the open verdict; a CONTRACT violation is not recoverable by proceeding, because proceeding means acting on a control the author believes is enforcing and which is not.

**A new `Action` value with no producer is a landmine.** `Action.ESCALATED` sat in the enum from before S3, emitted by nothing and referenced only in one test's tolerance list — so `_ACTION_SEVERITY`, added by S6, simply had no key for it, and `_ACTION_SEVERITY[before.action]` is an unguarded lookup. S3 was the first code that could emit it, and without the entry that lookup raises `KeyError` into the fail-open handler and turns an escalated verdict into a silent `allowed`. **Every new `Action` value a seam adds must be cross-checked against every severity, ordering or lookup table keyed by action, in the same PR that adds it.** An enum member with no producer is not inert; it is a dormant `KeyError` waiting for the first seam that produces it.

## 5. Tests each seam must ship with

- **Non-vacuity, both directions:** with the extension registered the behaviour changes as claimed; with it removed the identical input yields the open verdict. Stash/confirm-fail/restore on every commit.
- **Zero-movement gate:** corpus oracle byte-identical with no extensions, run once per PR.
- **Inert-stubs audit:** every seam adds a line to `test_inert_stubs_audit.py` proving a bare sensor has no extension attached and no seam changes a verdict.
- **Grep tripwires:** S7's literal-comparison grep; S11's "no cached `_blocked_urls` reference"; S12's "all five verbs call `_egress_headers`".
- **Performance:** with no extensions, median scan latency unchanged within noise on the README benchmark (the last two audits measured ~1.3 ms; the budget is 3 ms).
- **No silently-empty coverage:** a sabotage or fixture that silently produces zero coverage — skip-on-no-match, an empty fixture set, a sabotage whose anchor no longer matches — is the same failure class as a decorative test. **Assert non-empty; never skip silently.** S3's first draft hardcoded candidate flag-band strings, found none, and skipped nine of its own core tests on a green run; its fixtures are now derived from the committed corpus and assert. The same applies to sabotage harnesses: one S11 sabotage here "passed" only because the caching it introduced never engaged, which proves nothing about the test.
- **Break each boundary independently:** when a value crosses more than one boundary — parsed here and evaluated there, validated here and enforced there — the non-vacuity sabotage must break **each boundary separately**. A fix proven at the parse boundary alone does not prove the evaluate boundary. **S2 is the precedent:** `extra_conditions` was threaded into `parse_action_policy` and the parse-time tests went green, while `evaluate()` never received it and silently dropped every registered condition — which does not merely fail to fire, it WIDENS the rule the condition was written to narrow. Sabotaging only "the parser rejects unknown keys" could never have caught it; the revert has to be "parsed yes, evaluated no" specifically. Note also which DIRECTION discriminates: under that bug a *matching* condition still let the rule fire, so only the *declining* case goes red. Pair this with the both-directions rule above — the direction that agrees with the broken behaviour proves nothing.
- **Verification order:** run the full gate (suite + oracle) **AFTER** any sabotage / revert-and-restore sequence completes, never before it. A revert performed with `git checkout <ref> -- <path>` stages the change in the INDEX even when a `cp`-based restore afterwards touches only the working tree, so the revert survives in the index and the next `git commit` sweeps it in. **`git status` must show a clean tree before a "passed" result is trusted**, and the gate must be the last thing run — not the last thing run *before* the risky step. **Precedent, from the PR that added the rule above:** verifying the S2 fix required reverting `authz/policy.py` to its merged state; the working tree was restored with `cp`, the index was not, and the next commit silently deleted 58 lines and undid the fix on the pushed branch. It was caught by reading `git status` (`MM`) after the fact, not by the gate — the full suite had been run *before* the verification rather than after, so a green run was recorded against a tree that no longer existed.
- **A negative on one surface is not absence:** where two systems can independently enforce or record the same fact, check **both** before treating either as authoritative — and distinguish a genuine negative from an INCONCLUSIVE one. This is the census rule generalized past code: it applies to tooling and infrastructure exactly as it applies to a design doc's site list. Worked example from this repo: "is `main` protected" is answerable at the legacy `branches/main/protection` endpoint AND at the rulesets API, and a repo with rulesets only returns `404 Branch not protected` from the legacy one — the same answer an unprotected branch gives. Checking org-level rulesets additionally returned `404` for want of the `admin:org` scope, which is **not** evidence of absence; `rules/branches/main` is the composite endpoint that subsumes it, and that is the one worth trusting. The failure mode is identical to S2's: a check that passes because it is looking at the wrong layer reads exactly like a check that passes because the thing is fine.
- **A declared interface is proven complete by call sites, not by green tests:** at the point any multi-method interface is considered stable, **grep every method name against the full tree** and confirm each is invoked somewhere outside the interface's own definition and its tests. Tests passing proves the wired methods work; it says nothing about the ones nobody wired, because an unwired hook has no failing behaviour to observe — it is silence, and silence is what a correctly-declining hook also looks like. **Precedent, this seam set:** two of thirteen `SensorExtension` hooks were declared and never wired — `enforcement_policy()` and `outbound_headers()` — and neither was caught until an explicit close-out grep at PR 7. Every earlier grep had been per-SEAM ("is S9 wired?"), which is the wrong axis: it can only find what you already went looking for. The per-INTERFACE sweep is what surfaced them, and it is the same failure class as `Action.ESCALATED` (a declared enum value with no producer) restated for methods. A declared surface with no consumer is not inert; it is a promise the docstring makes and the code does not keep.

## 6. Sequencing — seven PRs, each independently mergeable

1. **S7** enforcement policy object (four sites + grep tripwire). Everything else reads it.
2. **S1 + S5 + S6** extension object, attach, gate chain, verdict transform, ordering tests. BUILT.
3. **S2** policy conditions through `parse_action_policy`. BUILT.
4. **S3** escalation chain in `LocalScanner`, flag-band cap, degraded signal, manifest health. BUILT.
5. **S9 + S10 + S11** trust, destination policy, blocked-URL provider. BUILT.
6. **S12** egress header consolidation, with `inject_context` wiring behind a default-off flag. BUILT (extension `outbound_headers` merging still design).
7. **S4 + S8 + S13** before_scan, on_response, tools declared. BUILT — closes the seam sequence.

Then release open (1.12.0), pin it, and build the enterprise package: `BrainReporter`, the quarantine gate, `watch` policy, `trust_below` condition, AGT destination policy, the Brain escalator, identity/context modules. The parity guard flips to "enterprise ⊇ open" and stays green by construction.

## 7. Open items carried, not decided here

- SSE-over-non-streaming responses are unscanned by accident on the egress patch (filed separately).
- The paid tool path has no ML layer (SDK#8); S3 is on `LocalScanner.scan`, which `_scan_tool_call_impl` bypasses. Whether the tool path should escalate is a product decision that predates this work.
- Whether S2 should let an extension *narrow* open's condition set (it currently can only widen). No use case today.
- Self-hosted Brain entitlement check (backlog).
- **`SensorExtension.enforcement_policy()` is declared and never called** — [#13](https://github.com/delphisecurity/xaidr/issues/13). Either wire it or delete it; leaving it declared is the option that misleads. Needs a decision on whether an extension may REPLACE the sensor's enforcement policy, and whether it may strengthen one (every other seam may only move in the safe direction).
- **S12's `outbound_headers` collision-merge rule is not implemented** — [#14](https://github.com/delphisecurity/xaidr/issues/14). The consolidation and the default-off provenance flag shipped in PR 6; merging each extension's headers, with "may add, never overwrite an open one", did not.
