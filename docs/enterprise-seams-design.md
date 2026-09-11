# Enterprise seams for open `xaidr` — design against `864243e`

**Status:** S7 built (PR 1); S1 + S5 + S6 built (PR 2); S2 built (PR 3, completed in PR 5); S3 built (PR 4); S9 + S10 + S11 built (PR 5). S4, S8, S12, S13 still design. Base: `delphisecurity/xaidr` main at `864243e` (release 1.11.0); the seam line numbers in §2 are on that commit and have since shifted — read them as "which function", not "which line". PR #3 (ASI/LPCI rules) shifts `local.py` by +34 lines and touches no seam site.
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

### S4 · before_scan — `DelphiSensor.scan` (`sensor.py:774`)

Called once per entry point (`scan`, `scan_output`, `scan_a2a`, `scan_tool_call`) with the built `ScanRequest`, before the gate (S5). Returns `Optional[ScanResult]`; a value short-circuits everything including telemetry, so it is reserved for "this request is not ours" cases. The enterprise use is context enrichment: the extension mutates a `context` mapping on the request (principal, agent, trace from its contextvars). `provider` and `parent_context` are already open kwargs (`:779`, `:781`) and need no hook.

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

### S8 · on_response — `ProtectedHttpClient._scan_response` (`sensor.py:2551`, was H9)

After the open output scan, every extension receives a `ResponseView`: provider (from the existing host table), status, URL host, content-type, and a lazily parsed JSON body accessor. No streaming (the egress patch already skips `stream=True`; the SSE-with-no-stream-kwarg case is a separate bug, filed). This is where the token-usage extractor for the ledger lands later, as an extension in open, emitting `llm_usage` events through the reporter.

### S9 · subject trust — `evaluate_policy` callers (was H11), BUILT

**Census correction:** `build_request` has exactly ONE caller and it is `local_policy.py`, inside `evaluate_policy` — the sensor never calls `build_request`. The two hardcoded `trust=None` sites are calls to `evaluate_policy` (`sensor.py`, tool path and HTTP destination path). The count of two was right; the function and the file were both wrong. The inert-stubs assertion is at `:349`, not `:304`.

`evaluate_policy(..., trust=...)` already takes a trust parameter and both callers hardcode `None`. Replace with `self._subject_trust(agent_id)`, which asks each extension in order and returns the first non-`None`. `tests/test_inert_stubs_audit.py:304` asserts `not hasattr(s, "_trust_score")`; reworded to assert a bare sensor's `_subject_trust()` returns `None` and no attribute stores a score.

### S10 · destination policy — `ProtectedHttpClient._check_destination` (was H12), BUILT

Before the operator blocklist check (`:2434`), each extension's `destination_policy(DestinationView)` may return a block result. **Census correction:** `dest_id` is NOT computed once up front — on the merged tree it is computed INSIDE the blocklist branch, only after a block has already fired. The view therefore computes it lazily and only when an extension is attached, so a bare sensor does not start paying for a parse it never needed. It carries the host only, never the URL or query.

**This seam makes #5's forward-looking sabotage live.** PR 2 added `except (DelphiBlockedError, _VerdictStrengthenedError)` to `_check_destination` and reported honestly that the clause was UNREACHABLE, because nothing on that path could raise it. S10 puts extension code inside that function for the first time; the contract errors now share an `_ExtensionContractError` base (see §4) and the clause is what stops a mis-written `destination_policy` becoming a silently permitted destination. The enterprise AGT URL policy plugs here. The three paid `print`s that leaked full URLs do not come across; the open host-only emission is the only path.

### S11 · blocked URLs provider — one reader, two mutators (was H13), BUILT

The reader at `:2435` holds `self._sensor._blocked_urls`, and `unblock_urls` rebinds the list at `:1692`, so any provider that caches a reference goes stale. Design: `_effective_blocked_urls()` computed at read time as `self._blocked_urls + [u for ext in extensions for u in (ext.blocked_urls() or ())]`, called at `:2435` on every check. No refresh hook is needed; a provider that wants freshness returns a fresh sequence each call and rate-limits itself. Test: register a provider whose list changes between two calls and assert the second call sees the change. Also tested: `unblock_urls` composed with a provider — the operator's removal takes effect while the extension's contribution survives the rebind, which is exactly the staleness a cached reference produces. An operator cannot `unblock_urls` an extension's entry; that list is the extension's, and letting the operator delete from it would make the enterprise control removable by the thing it constrains.

### S12 · outbound headers — five egress verbs (`sensor.py:2579`, `:2588`, `:2597`; none on `:2603`, `:2612`; was H14)

Consolidate: one `_egress_headers(dest) -> dict` used by all five verbs (GET and DELETE currently write no headers at all). It writes `X-Delphi-Source-Agent`, then **calls `provenance_chain.inject_context`** (`provenance_chain.py:355`, exported, and never called from the sensor's own egress today), then merges `ext.outbound_headers(dest)` from each extension. Extensions may add headers, never remove or overwrite an open one (collision raises at call time, once, then the extension's header is dropped).

Wiring `inject_context` is an open behaviour change in its own right and gets its own commit and test (a GET through `protect_http` carries `x-openA2A-chain`). It closes the "writer exists, unwired" gap on the open side; the paid "reader with no writer" gap then closes by inheritance.

### S13 · tools declared — `Sensor.protect_tools` (`sensor.py:1956`, was H15)

After wrapping, call `ext.on_tools_declared(tools)` once with `ToolView`s (name, description hash, `args_schema` hash). This is the seam the tool-definition-drift work will use; the enterprise package uses it to register the tool inventory with the Brain.

### Eliminated: telemetry hook

Paid's hard-wired flush is replaced by `BrainReporter(Reporter)` through the existing `reporter=` kwarg (`sensor.py:254`, Protocol at `reporters.py:67`). Signed batches, `capture_content=False` default, `contentCaptured` flag on every event so the Brain's `:1329` path can record "attribution unavailable, content capture off" instead of returning zero rows.

## 3. Ordering, in one place

Per entry point, after S7's policy object is in place:

```
build ScanRequest
S4  before_scan            (may short-circuit; no telemetry)
S5  gate chain             (circuit, then extensions; a gated verdict skips everything below)
local scan → S3 escalators (flag band only)
telemetry enqueue          (true verdict)              ← unchanged, :911/:1125/:1654
_breaker_observe           (true verdict)              ← unchanged, :918/:1131/:1661
_apply_mode                (open downgrade, then S6)   ← :919/:1132/:1662
return
```

Invariants pinned by tests: (a) a gated verdict never reaches enqueue; (b) enqueue and observe see the pre-S6 verdict; (c) S6 cannot strengthen; (d) S3 runs before enqueue so the escalated verdict is what telemetry records.

## 4. Fault handling contract

Per extension per hook per sensor: first fault logs ERROR with extension name, hook name, our own module:lineno, and the sentence "this control is inert until the sensor is rebuilt"; subsequent faults are counted, not logged. `manifest.faults` exposes the set. Exception: `on_attach` raises (construction), and S6 strengthening raises (contract violation, not environment).

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

## 6. Sequencing — seven PRs, each independently mergeable

1. **S7** enforcement policy object (four sites + grep tripwire). Everything else reads it.
2. **S1 + S5 + S6** extension object, attach, gate chain, verdict transform, ordering tests. BUILT.
3. **S2** policy conditions through `parse_action_policy`. BUILT.
4. **S3** escalation chain in `LocalScanner`, flag-band cap, degraded signal, manifest health. BUILT.
5. **S9 + S10 + S11** trust, destination policy, blocked-URL provider. BUILT.
6. **S12** egress header consolidation, with `inject_context` wiring as its own commit.
7. **S4 + S8 + S13** before_scan, on_response, tools declared.

Then release open (1.12.0), pin it, and build the enterprise package: `BrainReporter`, the quarantine gate, `watch` policy, `trust_below` condition, AGT destination policy, the Brain escalator, identity/context modules. The parity guard flips to "enterprise ⊇ open" and stays green by construction.

## 7. Open items carried, not decided here

- SSE-over-non-streaming responses are unscanned by accident on the egress patch (filed separately).
- The paid tool path has no ML layer (SDK#8); S3 is on `LocalScanner.scan`, which `_scan_tool_call_impl` bypasses. Whether the tool path should escalate is a product decision that predates this work.
- Whether S2 should let an extension *narrow* open's condition set (it currently can only widen). No use case today.
- Self-hosted Brain entitlement check (backlog).
