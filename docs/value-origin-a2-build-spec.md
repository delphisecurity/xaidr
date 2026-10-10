# A2 build spec: the request scope (D1–D5) and M10's remainder

Written before any code, as the owner's handoff requires (STEP 3). Base:
`832e642` on `feat/value-origin-seams` (main `0502c99` merged in at `8ce8dc4`).
Every number here was measured in this session against the tree or a wheel built
from it, and each phase below names the in-tree test or driver that reproduces it.
This was written before any code. Where building a phase, or its fresh-context
review, changed the design, the change is marked in place as *Corrected*.

## 0. The rulings, and where the real code disagrees with them

The owner asked to be told plainly when a ruling contradicts the code. Four
places do, in part. None reverses a ruling. Each changes how it is built.

### D1. `xaidr.flow()` on `contextlib.ContextDecorator`

Ruling: `with xaidr.flow(...)` and `@xaidr.flow(principal=...)` both work.

Measured on CPython 3.10.20 and 3.12.2 with a session probe (a `ContextVar`, a
class-based and a `@contextmanager` decorator, one `async def` handler, two
threads through one decorated handler). P1's tests reproduce each row in the
tree:

```
class     async handler body saw V = None   (sync scope exited at coroutine creation)
class     concurrent sync calls: seen=[(0, 'alice'), (1, 'alice')] errors=["RuntimeError: <Token ...> has already been used once"]
class     decorated fn receives __enter__ value? args=((), {})
generator async handler body saw V = None   (sync scope exited at coroutine creation)
generator concurrent sync calls: seen=[(0, 'alice'), (1, 'alice')] errors=[]
generator decorated fn receives __enter__ value? args=((), {})
```

Three consequences, all stated rather than worked around:

1. **A decorated `async def` handler is NOT scoped.** `ContextDecorator` wraps
   the call that CREATES the coroutine, so the scope opens and closes before the
   body runs. The same is true of generator and async-generator functions (the
   body runs at iteration). A silent no-op is the worst outcome for a security
   scope, so `flow()` used as a decorator **refuses** those three kinds of
   function with a `TypeError` that names the `with` form. *Corrected after P1's
   review:* it also refuses, at call time, ANY call that returns an awaitable or
   a generator. An object with an async `__call__`, or a sync wrapper around an
   `async def`, passes a check of the function itself. Async hosts write
   `with xaidr.flow(...):` inside the handler. Supporting `async def` properly
   would need a `__call__` that is no longer `ContextDecorator`'s; that is a
   ruling for the owner, not something this build decides (§7, Q-A).
2. **A class-based decorator shares one instance across concurrent calls**, and
   two pool threads through one decorated handler raised
   `RuntimeError: ... Token has already been used once`. Thread pools are exactly
   where D1 says the decorator form lives. `flow()` therefore re-creates its
   context manager per call (`_recreate_cm`, the hook `contextlib`'s own
   `_GeneratorContextManager` uses). The generator row above is the proof that
   per-call re-creation is sufficient.
   *Corrected after P1's review:* per-call re-creation covered the decorator but
   not one `flow()` object used with `with` on several threads. The built design
   keeps each scope's entry on a per-CONTEXT stack instead (§1), which makes any
   number of uses of one instance safe, so `_recreate_cm` was removed. *Corrected
   again:* a nested scope JOINS the open one (§1). The second design's reviews
   showed a replacing nested scope opens the tier gate.
3. **The decorated function never receives the yielded correlation id.**
   `ContextDecorator` calls the function with its own arguments only. A handler
   that needs the id reads `xaidr.provenance_chain.current_correlation_id()`,
   which already exists. No new export is added for it.

### D2. S-2 removed: no implicit ledgers

Ruling: free now, breaking later. Confirmed free: the latest published wheel
(1.19.0, `uv pip install --no-deps --target w119 xaidr==1.19.0`) has no
`value_origin` package and its `begin_flow` binds no ledger, so no released host
reads an implicit ledger.

What the code says it costs, measured by running every test file that names
value origin or a flow (24 files, 448 tests) with S-2 simulated by a pytest
plugin that replaces `_bind_for_input` with one returning the explicit ledger
or a throwaway that is never bound (the same replacement STEP 2 used, §5):

```
FAILED tests/test_value_origin_m6.py::test_m6_principal_input
FAILED tests/test_value_origin_m5.py::test_s25_origin_without_a_flow
2 failed; every other test in the 24 files passed or xfailed as before
```

- `test_m6_principal_input` pins three S-2 behaviours: S30 (`no_flow` where it
  wants `principal_undeclared_span`/`unresolved`), the host-recorded hop
  (`ledger_absent`), and Q21's `a2a_inbound_ends_implicit` (`no_flow` where it
  wants `unresolved`).
- `test_s25_origin_without_a_flow` wants `('no_flow', 'unresolved')` and gets
  `('no_flow', 'no_flow')`.

Both pin the ruling D2 reverses. They are rewritten to the new contract, not
deleted (§4, P2).

**Q21's mechanism becomes a no-op.** Q21 (ARCHITECTURE.md:981-994) ends the
previous request's implicit ledger on an inbound A2A message "through the same
'implicit bound → replaced' path that S-2 gives `record_principal_input`"
(`Sensor._vo_inbound_a2a`, sensor.py:2044-2055). With no implicit ledgers there is
nothing to end. Q21's guarantee (no carry into delegated work) then holds by
construction, but C-17's outcome for a flow-less host changes from "a fresh
ledger" to "no ledger". That is the D2 ruling's consequence, written down here so
it is not discovered later.

**The flow-less reuse xfail cannot become asserting as written.** Under the
simulation it still xfails, because its PRECONDITION asserts that user A's own
flow-less call is authorized (`assert a in AUTHORITY`). Under D2 a flow-less A
has no ledger either. The asserting form keeps the scenario and changes the
precondition: both A and B read `no_flow`, so there is nothing to carry (§4, P2).

### D3. Option (a)

Applied as ruled. Nothing in the code contradicts it.

### D4. The inbound scope (STEP 1)

The STEP 1 conditional stop did **not** fire, and the evidence for that is in §2.
`extract_context` gets the same scoped form, `xaidr.flow(inbound=headers)`, with
two differences the code forces. Both are at the edges, not in the lifetime:

- **Entry clears chain, correlation id and tiers before restoring.**
  `extract_context`'s early returns (provenance_chain.py:481-495) leave whatever
  the context already held, so a scope that only wrapped it would inherit stale
  state (§2.3).
- **Exit loosens the privilege-tier gate.** It always does for `flow(inbound=)`,
  and only conditionally for `flow()`. Documented and pinned as a counter-case
  (§4, P3).

And one the stdlib forces: a decorator is applied once, at definition time, so
`@xaidr.flow(inbound=...)` cannot take a request's headers. The `inbound=` form
refuses decorator use with a `TypeError` and is `with`-only.

### D5. Auto-scope on the CrewAI and Agents SDK hooks

STEP 2's condition: if D2 does NOT take these paths' coverage to or near zero,
the coupling of D2 and D5 was wrong. It does take it to zero (§5): 100% → 0% on
every path that had coverage. So the auto-scope on these two hooks is in A2, and
LangGraph stays deferred, as ruled.

Two things the measurement shows that the ruling did not anticipate. Neither
reverses it.

- **"Coverage" here means a ledger was bound, not that an origin was traced.**
  Every ledger-backed call on these corpora read `unresolved`, because no
  principal text named its destination. `unresolved` and `no_flow` both allow, so
  on these corpora D2 changes the wire and no action.
- **A nested hooked run records model text as PRINCIPAL.** `Agent.as_tool` calls
  the patched `Runner.run` with the orchestrator MODEL's tool argument as `input=`,
  and the hook records it as principal. A sub-agent's call to a URL the model
  chose then reads `principal_undeclared_span` (measured, flow-less, before D2).
  Under any explicit flow the same happens, because an explicit ledger keeps
  recording (`_ledger.py:181-182`). That was read, not run. An auto-scope that
  re-binds for the outer run would carry this into every Agents SDK host. P4
  therefore does not record a nested hooked run's input as principal (§4, P4;
  §7, Q-C).

## 1. The request scope

```python
with xaidr.flow(principal="user:alice") as corr:      # corr: the flow's correlation id
    agent.invoke(...)

@xaidr.flow(principal="service:billing")               # sync handlers only (D1.1)
def handle(request): ...

with xaidr.flow(inbound=request.headers) as corr:      # corr is None if nothing was restored
    handle(request)
```

**As built (third design, after two fresh-context reviews).** Each open scope is
an entry on a per-CONTEXT stack, a ContextVar. The five request vars are
`_chain_ctx`, `_corr_ctx`, `_tiers_ctx` and `_inbound_ctx` in provenance_chain.py,
and `_LEDGER` in value_origin/_ledger.py.

**Entering a scope:**

- **The first scope in a context is FRESH.** It saves the five vars' values and
  runs `begin_flow()`'s body.
  - If the fresh ledger did not bind, it runs on no ledger, not the one before it.
  - Opened over an inbound or tier-delegated context that no scope owns (the plain
    `extract_context`, say), it keeps that context's chain, tiers and inbound mark,
    which only tightens the tier gate. It still gets its own ledger.
- **A scope opened while another is open in the same context JOINS it.** It is
  the same request, so it changes nothing, and its `principal=` is not applied.
  This makes middleware's request scope plus a decorated handler one request,
  with the delegation evidence the tier gate reads.
- **A scope opened inside a generator's body is refused with a `TypeError`.**
  Generators driven by `@contextmanager` or `@asynccontextmanager` are exempt,
  because the with-statement drives them in order.
- **Anything that faults while opening** leaves the body running in the flow it
  was entered in, and is counted. It never reaches the host.

**Leaving a scope:**

- **An exit closes its entry AND every entry opened inside it.** A FRESH entry
  also puts its saved values back.
- **`clear_flow()` closes every open scope in the context the same way.** A scope
  closed like that exits later without effect or fault.
- **An exit with no entry in the context it runs in** (another thread or task, a
  second exit) changes NOTHING there, and is counted.
- **A fault while putting values back** clears that same context to no flow.

Exit never raises (owner, M7), and the body's exception propagates unchanged.
Faults are counted; the 1st, 10th and 100th are logged at ERROR with the count.

**Why it is shaped this way.** These are the reviews' measurements; each is now a
check that is red against the design it caught (§4 P1).

*First design, `3a6c820`, corrected:* ContextVar TOKENS in a list on the instance.
- The fallback cleared the exiting context. That opened an unrelated inbound
  request's tier gate.
- Out-of-order exits silently brought back a closed scope.
- One instance shared across threads lost the threads' outer flows.

*Second design, `325f12c`, corrected:* values on a per-context stack, with an
out-of-order exit handing its values to the scope above it.
- A request scope that exited while a generator's scope it opened was still open
  did not end the request: user B started in the generator's flow. That was a
  regression.
- A parked generator's late exit put stale values into a later request on the
  same thread.
- A nested `flow(principal=...)` still opened the tier gate 4-to-1, because it
  replaced the chain. Keeping the inbound mark was not enough.
- The never-closed generator scope is what all of these share, so the third design
  refuses scopes held by generator bodies and makes nested scopes join.

**Not reset by the scope**, deliberately: `provenance._origin_ctx` (it has its
own `origin_scope`; the docstring and docs/api.md now say so), `sensor._VO_CALL_WIRE` and `_vo_seams.RESULT_SEAM` (both are
per-call and set/reset around each call already), and `integrations/crewai.py`'s
own var. Each is checked in P1's review.

## 2. STEP 1: what `extract_context` binds, who calls it, how long it is meant to live

Three fresh-context verifiers each tried to refute the stop condition (workflow
`d4-extract-context-verify`), and one measured. The findings:

### 2.1 It is not on the inbound A2A path

- **No module under `xaidr/` calls it.** It is a public host API (`__init__.py:12`).
- **The sensor's own A2A receive does not reach it.** `scan_a2a(received=True)`,
  reached from LangChain through `route_inbound_scan`, calls `mark_inbound()`
  (sensor.py:2336) and `_vo_inbound_a2a()` (:2266), never `extract_context`.
  ARCHITECTURE.md:96 records the same.
- **Its documented use is a generic inbound HTTP call** (docs/provenance.md:28-33).
  The writer it pairs with, `inject_context`, runs on every `ProtectedHttpClient`
  verb (sensor.py:4608).
- **Two texts disagree with that.** The `no_flow` warning (sensor.py:2607-2612) says
  "call extract_context() on an inbound A2A request". The sentinel spec C-17 reads
  "an inbound A2A message starts a fresh ledger (`extract_context` →
  `bind_fresh_ledger`)". The code took Q21's other route. D3's warning-text
  change fixes the first (§4, P1).

### 2.2 It is meant to live for the whole request, and no longer

- Every in-repo caller brackets it with `clear_flow()`
  (tests/test_audit_sep05_bypasses.py:389-397, tests/test_privilege_tiers.py:106-120,
  tests/outside/drivers/m5_binding.py:59-63 in a `try/finally`).
- The inbound mark is read on every `scan_tool_call` (`is_delegated` through
  `_least_privileged_tier`, sensor.py:3096 → :2678, :2693), so it must last until
  the request's last tool call.
- That is `begin_flow()`'s documented lifetime too (docs/api.md:65). A with-block
  around the request IS that lifetime. So it is the same scoped form, not a
  different shape.

### 2.3 Entry must start from a clean context

`extract_context` returns early when headers are absent or carry no correlation
id (provenance_chain.py:481-495), and an early return leaves the chain,
correlation id and tiers the context already held. A scope that only wrapped it
would inherit whatever was there at entry. `flow(inbound=)` therefore sets all
three to `None` before calling it (§1). P3's first test pins that with stale
state planted directly in the ContextVars.

A related observation about the plain `extract_context` outside any scope was
reported to the owner separately. It is not A2's, and it is not addressed here.

### 2.4 The exit direction is the real difference

Measured with a prototype of the scope (the five vars tokened on enter and
reset on exit; tier-1 receiver; `TIER_POLICY` from tests/test_privilege_tiers.py).
P3's tests reproduce the rows in the tree.

**Inside vs after a simulated `flow(inbound=)` exit:**

| case | inside | after exit |
|---|---|---|
| valid tier-4 sender headers | `is_delegated=True`, tier 4, `approval_required` | `False`, tier 1, `allowed` |
| chain and tiers stripped | `approval_required` | `allowed` |
| `extract_context({})` | `approval_required` | `allowed` |
| `extract_context(None)` | `approval_required` | `allowed` |

**The same mechanism around `begin_flow`:** no tier verdict changes on exit. The
one exception is an in-process tiered hop: `flow(principal=)` plus
`record_hop('upstream', tier=4)` reads `approval_required` inside and `allowed`
after.

**Where it matters:** work that runs AFTER the block in the same request.

- **Not affected:** work started inside the block with `create_task`,
  `call_soon` or `propagate_context` copies the context. It still read
  `approval_required` after the parent block exited.
- **Affected:** a body created inside the block but consumed after the handler
  returns, as a streamed response is, runs with the mark reset. That reopens the
  4-to-1 bypass the `extract_context` docstring records.

Starlette itself was not run. The rule for hosts is in the docs (P3): the scope
must cover the response body.

## 3. Phases

Five phases, built in this order. Each is one push. The standing bar applies to
all of them: failing test first, watched red; only the affected tests plus every
seam touched; sabotage proof; verification from outside the process; a
fresh-context review; `PYTHONDONTWRITEBYTECODE=1` with a fresh
`PYTHONPYCACHEPREFIX`; the `-s` trailer checked before push.

Test runs use the dev-extra venv, since the shared `~/opena2a/.venv` lacks
`urllib3`/`hatchling` and REFUSES the `requires_dev_extra` tests:

```
PYTHONPATH=$WT PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=$(mktemp -d) \
  $DEVVENV/bin/python -m pytest -q -p no:cacheprovider <files>
```

**SEAMS** below is the 24-file set:
`grep -l 'value_origin\|valueOrigin\|begin_flow\|clear_flow' tests/test_*.py`
(448 tests, about 45 s). **TIERS** is tests/test_privilege_tiers.py,
tests/test_audit_sep05_bypasses.py and tests/test_prefix_failing_first.py, the
readers of `_inbound_ctx`/`_tiers_ctx`.

## 4. Per phase

### P1. `xaidr.flow()` (D1) and the open-flow test (D3)

> **STOPPED (2026-10-09), after the third design's fresh-context review.**
> `93d60a1` meets this phase's own counter-case on both counts, reproduced in
> the build session, not only relayed:
>
> - **Counter-case 1:** a fresh scope over an untiered upstream hop opens the
>   tier gate, `approval_required` -> `allowed`.
> - **Counter-case 2:** a worker created inside request A's scope makes job B's
>   scope join A, and B reads A's authority.
>
> Everything below describes `93d60a1` as built; it is not the phase's
> conclusion. See PROGRESS.md, "A2 build ... STOPPED in P1", and §7 Q-G.

*Corrected twice, after two fresh-context reviews (2026-10-08/09).* This section
first described the token design, then the second design. §1 records both. As
built:

**Files, and why each changes:**

- **`xaidr/provenance_chain.py`:** `_FlowScope(contextlib.ContextDecorator)`,
  `flow()`, the per-context scope stack and its rules (§1), and `clear_flow()`
  closing open scopes.
  - `__call__` is an override, not `ContextDecorator`'s own.
  - It refuses coroutine, generator and async-generator functions at decoration
    time.
  - At call time it refuses a call that returns a coroutine, an async generator,
    or a non-Future awaitable: a body that has not run.
  - It does NOT refuse a returned sync generator (a WSGI body: the app's work ran
    in the scope) or a Future (it runs in a copy of the scope's context).
- **`xaidr/value_origin/_ledger.py`, `__init__.py`:** `ledger_get()` and
  `ledger_set()`; the BINDING table names `flow()`.
- **`xaidr/__init__.py`:** exports `flow`.
- **`xaidr/sensor.py`, the once-per-sensor `no_flow` warning:**
  - It names `with xaidr.flow(...)` first, and states the plain pair's limitation.
  - For inbound requests it says to call `extract_context()` on the headers.
  - It drops "A2A" (§2.1).
  - *Corrected:* the second design's "inside that scope" is removed. A scope with
    a principal, then a header-stripped `extract_context` inside it, leaves the
    scope's principal chain, which reopens the stripped-header 4-to-1. P3's
    `flow(inbound=)` is the safe inbound form.
- **`docs/api.md`, `README.md`:** the scoped form first, and the plain pair's
  limitation. api.md also covers the decorator's refusals, generators, joins, the
  inbound case, and `set_origin()`.
- **Tests:**
  - **`tests/test_value_origin_flow_scope.py`** and its driver
    **`tests/outside/drivers/flow_scope.py`**, which the outside test runs from the
    built wheel.
  - The open-flow test in **`tests/test_value_origin_reuse.py`**: its D3
    flip-condition body, now correct.
  - **`tests/test_value_origin_m4.py`**.

**The driver's 19 cases,** each a check in the test module and from the wheel.
`_state` reads all five vars, and the tier-gate cases read the gate's VERDICT on a
privileged call, not only the inbound mark.

- `scope_that_raises`
- `nested_joins`
- `tier_gate`: a tier-4 upstream against a tier-1 receiver, through a plain
  inbound request, a request scope, in-process delegation and a decorated
  handler, plus a local positive control.
- `inbound_restored`
- `correlation_id`
- `threads`: the decorated handler at top level and inside per-thread request
  scopes.
- `shared_instance`
- `recursion`
- `refusals`: eight refused kinds; a WSGI body and a Future not refused.
- `generator_held`: sync, async and `ExitStack` refused; `@contextmanager`
  allowed.
- `foreign_exit` and `double_exit`: the stray exit lands in a request running
  inside its OWN scope.
- `outer_closes_inner`
- `request_raises_with_inner_open`: B starts clean, and C's scope is fresh.
- `clear_flow_closes_scopes`: a scope that never exits, then `clear_flow()`.
- `enter_faults`: at the save and inside `begin_flow`.
- `exit_fault`
- `fault_log`
- `bind_fault`

**Failing first.**

- Against `46cc8c4`: `7 failed, 4 passed, 2 xfailed`.
- Against the first design (`3a6c820`), the second design's checks: `10 failed,
  6 passed`.
- Against the second design (`325f12c`), these checks: `10 failed, 11 passed`.
  Each red names its consequence, for example:
  - `plain_inbound_in_decorated_handler: a tier-4 upstream's privileged call read
    'allowed' through xaidr.flow()`;
  - "user B started in {... 'chain': [{'agent_id': 'lib' ...": the regression;
  - "a fault while the scope opened (begin_flow) reached the host";
  - "a fault while putting the flow back left the closed scope's state";
  - "a scope opened in a sync_generator was not refused".

**Sabotage proofs** on the third design. The file hash was `45e6c98ca44209d9`
before and after each; every named check went red, then green after the restore:

1. No join → `nested_joins`, `threads`, `recursion`.
2. A fresh scope drops the delegation evidence → `tier_gate` ("read 'allowed'").
3. An exit does not close the scopes opened inside it →
   `request_raises_with_inner_open` ("the next request's scope JOINED the
   leftover").
4. A stray exit closes the scope on top where it runs → `foreign_exit` and
   `double_exit` ("tier verdict 'approval_required' -> 'allowed'").
5. `clear_flow()` leaves open scopes → `clear_flow_closes_scopes`. *Corrected while
   building:* the first version of this case passed the sabotage, because its
   scope exited itself. The case now leaves the scope open.
6. No refusal of a scope held by a generator → `generator_held`.
7. Call-time refusal of coroutines only → `refusals` (`returns_async_generator`).
8. A returned generator or Future refused too → `refusals` (the WSGI app).
9. A fault while opening reaches the host → `enter_faults`.
10. A failed restore leaves the closed scope's state → `exit_fault`.
11. No guard when the fresh bind did not take → `bind_fault`.

**Outside the process:** the same driver from the built wheel
(`tests/outside/test_p1_flow_scope_from_the_wheel.py`), with no framework. The
real `create_agent` reuse rows are in P5's acceptance driver.

**Test selection:** `tests/test_value_origin_flow_scope.py`,
`tests/test_value_origin_reuse.py`, `tests/test_value_origin_m4.py`, SEAMS,
TIERS, and the outside P1, M4 and M5 tests.

**Counter-case, the result that would prove P1 wrong:** any composition of scopes,
exits, `clear_flow()` and decorated handlers in which either:

- a request's tier-gate verdict on a privileged call is looser than the same
  request's verdict with no `xaidr.flow()` anywhere; or
- a later request on the same thread starts in an earlier request's flow or
  ledger.

The `tier_gate`, `foreign_exit`, `double_exit`, `request_raises_with_inner_open`,
`clear_flow_closes_scopes` and `scope_that_raises` cases measure it.

**Known and stated, not fixed:**

- The plain pair's limitation (D3).
- A sync handler's returned generator runs outside the scope.
- A Future the handler returns keeps running after the scope closes, in the
  scope's copied flow. That is the request's own work.

### P2. S-2 removed (D2)

**Files:**

- **`xaidr/value_origin/_ledger.py`:**
  - `_bind_for_input` returns the explicit ledger or `None`.
  - `record_principal_input` with no ledger records nothing and returns
    `RecordOutcome.NO_LEDGER`.
  - The BINDING table loses the implicit rows.
  - The V-27 paragraph ("An implicit ledger lives for one request...") is
    replaced by the D2 rule.
- **`xaidr/sensor.py`:** `_vo_inbound_a2a` (2044-2055) and its call (2266) are
  deleted. Q21's guarantee holds by construction. The docstring that cites S-2
  is updated. The A2A path keeps `mark_inbound()` unchanged.
- **`tests/test_value_origin_m6.py`:** S30, the host-recorded hop and
  `a2a_inbound_ends_implicit` assert `no_flow` and `ledger_absent` for flow-less
  requests. Each assertion message names D2.
- **`tests/test_value_origin_m5.py`:** `test_s25_origin_without_a_flow` asserts
  `('no_flow', 'no_flow')`.
- **`tests/test_value_origin_reuse.py`:** the flow-less test becomes asserting.
  A and B both read `no_flow` on one pool thread, and `ledger_bound()` is False
  after A's input scan.
- **`tests/outside/drivers/m6_principal_input.py`** and
  **`tests/outside/test_m6_from_the_wheel.py`:** same contract from the wheel.
- **`ARCHITECTURE.md`**, **`docs/value-origin-enforce.md`**,
  **`docs/value-origin-rulings.md`:** the S-2, V-27 and Q21 rows marked "reversed
  by D2 (owner, 2026-10-08)" in place, not deleted (retraction rule).

**Failing tests first:**

- `test_a_flow_less_input_binds_no_ledger`: after `Sensor.scan(..., direction="input")`
  with no flow, `ledger_bound()` is False. Red today: True.
- The rewritten flow-less reuse test. Red today: A reads `principal_undeclared_span`.

**Sabotage proof:** restore `_bind_for_input`'s implicit `_LEDGER.set`.
`test_a_flow_less_input_binds_no_ledger` and the reuse test go red; the
explicit-flow tests in SEAMS stay green. That is the discriminating half: the
removal touched only the implicit path.

**Outside the process:** the m6 driver from the wheel. A new
`tests/outside/drivers/s2_flowless.py` runs real `create_agent` with no flow and
asserts every tool call reads `no_flow` and no ledger is ever bound, sampling
`ledger_bound()` from inside a tool.

**Test selection:** SEAMS, `tests/outside/test_m6_from_the_wheel.py`,
`tests/outside/test_m5_from_the_wheel.py`, the new outside test.

**Counter-case:** any explicit-flow verdict moves anywhere in SEAMS, or any
flow-less call in the 410-row benign_toolcalls corpus reads a ledger-backed wire.
The first means the removal overreached into explicit flows; the second means an
implicit path survived. Both are measured at P2's head, before P4 adds any scope:
SEAMS is run, and the STEP 2 drivers run the full corpora with no flow from the
real wheel. They must reproduce §5's AFTER column without the simulation.

### P3. `flow(inbound=)` (D4)

**Files:**

- **`xaidr/provenance_chain.py`:**
  - `flow(inbound=headers)`: entry clears chain, correlation id and tiers, then
    runs `extract_context`.
  - `inbound=` together with `principal=` or `correlation_id=` raises a
    `TypeError`.
  - Decorator use with `inbound=` raises a `TypeError`.
- **`docs/provenance.md:28-33, 69-73`:** the receive side becomes
  `with xaidr.flow(inbound=request.headers):`, and the scope must cover the
  response body (§2.4).
- **`docs/privilege-tiers.md`:** one paragraph: the inbound scope's exit loosens
  the tier gate for anything after it.
- **`tests/test_value_origin_inbound_scope.py`** (new).

**Failing tests first:**

- `test_inbound_scope_starts_from_a_clean_chain_and_tiers`: plant a stale chain,
  correlation id and tier list directly in the three ContextVars, then enter
  `flow(inbound={})`. Inside, `current_chain()` and `current_correlation_id()`
  are `None` and the tier ceiling is the inbound default (4). Red with
  entry-clear removed: the planted chain is visible inside the scope.
- `test_inbound_scope_marks_every_tool_call_in_the_block`: two tool calls and an
  output scan inside the block all read `is_delegated() == True`.
- `test_inbound_scope_exit_restores_a_local_context`: after exit,
  `is_delegated()` is False and `ledger_bound()` is False.

**Sabotage proof:** delete the entry clear; the first test goes red with the
planted chain visible inside the scope. Restore byte-identical.

**Outside the process:** `tests/outside/drivers/inbound_scope.py` from the wheel
runs, on a real pool thread, a request inside `flow(inbound=headers)` with valid
headers and one with none. Each must read the inbound ceiling on every tool call
inside the block and a local context after it.

**Test selection:** the new file, TIERS, SEAMS,
`tests/outside/test_m5_from_the_wheel.py`, the new outside test.

**Counter-case:** a body created inside the scope and consumed after exit. A
generator that runs a tool call reads `is_delegated() == False` and the tier
gate opens. This is the documented limitation, not a defect of the scope. It is
pinned by `test_a_body_consumed_after_the_scope_runs_outside_it`, which ASSERTS
the open gate. The assertion message says the host must cover the response body
and points to docs/provenance.md. If someone makes exit "sticky" for the inbound
mark, this test goes red and forces the docs to change with it.

### P4. Auto-scope on the CrewAI and Agents SDK hooks (D5)

In scope because STEP 2 measured that D2 takes these paths' coverage to zero (§5).
LangGraph and `create_agent` stay deferred (D5): the 3.10 `create_task(context=)`
gap and streaming are out of A2.

**Behaviour:** each hooked entry point runs inside `flow()` when, and only when,
no flow is active at entry. A host that already opened a flow keeps it, with its
principal, chain and ledger. The scope covers the input scan, the call and the
output scan, and closes on return, raise or halt.

**Files:**

- **`xaidr/autopatch/core.py`:** `make_wrapper` gains `scope: Optional[Callable[[], ContextManager]]`.
  When given, the wrapper's whole body (`_before`, the call, `_after`) runs inside
  `with scope():`. In the async wrapper that is inside the coroutine, so the
  scope lives in the awaiting task's context.
- **`xaidr/autopatch/frameworks.py`:** `_patch_crewai`'s `kickoff_factory` (Crew.kickoff)
  and `_patch_openai_agents`' `factory` (Runner.run, Runner.run_sync) pass
  `scope=_auto_flow`, where `_auto_flow()` returns `flow()` if
  `not is_flow_active()`, else `contextlib.nullcontext()`. The manifest entries'
  coverage text says so. `Runner.run_streamed` stays unpatched, and the manifest
  note already says why.
- **`xaidr/autopatch/core.py`** (same file): a ContextVar `_HOOKED_DEPTH`, raised
  for the duration of every scoped hook call. When the scope wrapper finds it
  already raised, the call is NESTED (an `as_tool` sub-run, a crew kicked off
  from a tool). A nested call's input is still scanned for detection, but it is
  not recorded as principal. `scan_text_boundary` passes `vo_record=False`
  through `Sensor.scan`'s existing input path. That path is a new keyword-only
  parameter, honoured only for `direction="input"`.
- **`tests/test_autopatch_auto_scope.py`** (new).

**Failing tests first:**

- `test_a_nested_hooked_run_does_not_record_its_input_as_principal`: a hooked
  run whose tool starts a second hooked run with model-chosen text naming
  `https://chosen.example/`. The sub-run's call to that URL must read
  `unresolved`, not `principal_undeclared_span`. Red today (measured, §0 D5).
- `test_crewai_kickoff_opens_a_scope_when_no_flow_is_active` and
  `test_agents_runner_run_opens_a_scope_when_no_flow_is_active`: a stub framework
  module of the same shape as the existing autopatch tests. Inside the call
  `is_flow_active()` and `ledger_bound()` are True; after it, both are False.
  Red: both False inside, under D2.
- `test_the_auto_scope_keeps_a_host_flow`: inside a host
  `flow(principal="alice")`, the hooked call sees the host's correlation id and
  chain head, unchanged.
- `test_the_auto_scope_closes_when_the_call_raises`, and the same when the input
  scan halts with `DelphiBlockedError`.

**Sabotage proof:** pass no `scope=` from the CrewAI factory. Its test goes red;
the Agents test stays green, which is the discriminating half. Then the reverse.

**Outside the process:** the STEP 2 drivers (§5), moved to
`tests/outside/drivers/crewai_coverage.py` and `agents_coverage.py`, run from the
real wheel with D2 and P4 built (no simulation). The expectation is the BEFORE
column of §5 restored. The exception is CrewAI shape B, which gains
ledger-backed verdicts it never had, because the scope now exists even when no
input was scanned; that difference is predicted and asserted. CI does not
install CrewAI or the Agents SDK (ci.yml:150), so these run locally behind
`XAIDR_ACCEPTANCE=1`, like §4's acceptance test.

**Test selection:** `tests/test_autopatch_auto_scope.py`,
`tests/test_autopatch*.py`, `tests/test_protect*.py`, SEAMS, and the two outside
drivers.

**Counter-cases, any of which proves P4 wrong:**

1. With the auto-scope built, a reused pool thread running two kickoffs
   back to back, the first raising, gives the second request any ledger-backed
   wire that came from the first. That would mean the scope does not close on
   raise in the framework's own execution path.
2. Coverage after P4 stays near zero on shape A. That would mean the tool hook
   runs in a context the entry scope does not reach (a worker thread with a
   fresh context), and the scope belongs somewhere else.

3. A nested `as_tool` run's model-chosen destination reads any principal wire.
   Measured by an outside driver that uses the real `Agent.as_tool`.

All three are measured by the outside drivers.

### P5. M10's four remaining findings, then the monitor-mode disagreement

M10 named four gaps between its measurement and §4 (PROGRESS.md, "Gaps against
§4 in this measurement"). Read as the four findings STEP 5 means:

1. **No B-designated-twin case.** It is added to
   `tests/outside/drivers/langchain_poisoned_read.py`. A designated
   `directory_lookup` (EXACT, `key_args=("query",)`) keyed by the principal's
   "Bob" returns `bob@corp.example`, and `send_email` to it is EXECUTED with
   `trusted_source`. Red first: the case does not exist.
2. **All cases ran in one process.** §4 says each case runs in its own process.
   The driver takes a case name, and the outside test runs one process per case.
   Red first: the test asserts each case's pid is distinct.
3. **A-off's "no valueOrigin anywhere" was checked on the send event only.** The
   check covers every captured event. Red first: point the check at all events
   on the current driver and see whether it already holds. If it does, record
   that the gap was in the check, not the code.
4. **The driver records only `send_email` events.** It records every tool event
   (`read_doc` and `send_email`), so (3) has something to check.

And the CI step §4 specifies: the `real-frameworks` job gains an acceptance step
with the JUnit under-collection guard copied. **D-async** is in the case table
and cannot pass until the async fix lands on its own branch (#38). It is a strict
xfail whose body names the flip condition: "turns XPASS when xaidr's LangChain
middleware implements `awrap_tool_call`; then make it asserting."

**The monitor-mode disagreement.** §4's A-enforce-monitor row says
"Event `action=flagged`". The sensor emits the TRUE verdict, `action=blocked`
with `enforcementMode=monitor`, before `_apply_mode` (sensor.py:2571-2588: emit at :2580, `_apply_mode` at :2583; M8b),
and every gate does this. The RETURNED verdict is `flagged`. The recommendation
standing since M10 is that §4 is the outlier. The build changes ARCHITECTURE.md
§4's row to "event `action=blocked`, `enforcementMode=monitor`; returned verdict
`flagged`", marked as corrected in place, and asserts exactly that in the driver.
No code changes. If the owner rules the other way, this is the one item in P5
that flips.

**Test selection:** `tests/outside/test_m10_acceptance_from_the_wheel.py` (new,
per case), with `XAIDR_ACCEPTANCE=1` locally.

**Counter-case:** under value origin OFF (A-off), any event carries
`valueOrigin`. That would mean the off switch leaks a field the consumer gate
(M9) withholds. It is measured over every captured event.

## 5. STEP 2 numbers

Measured from the wheel built from a clean archive of `5a5f575` (sha256
`ae86164c…`), installed `--no-deps` into a fresh venv with the framework's
current release, and run with `python -I`. The models are scripted, with no
network. One framework request per case, sequential, so each case is a request.
Each pass ran in its own process. BEFORE is unpatched. AFTER replaces
`_bind_for_input` with one that returns the explicit ledger or a throwaway that
is never bound. Every case ran (4,345 per pass: benign_toolcalls 410, FP-corpus
URL hosts 2,978, FP-corpus tokens 957), with no cap.

Coverage is the share of calls carrying a destination whose wire is
ledger-backed; `no_destination` is its own bucket. A fresh-context reviewer
rebuilt each venv from the frozen package list, re-ran every pass, and got
byte-identical per-case output. Two independent instruments agreed, one reading
the wire from telemetry only and one checking ledger identity per request.

| path | shape | corpus | n | BEFORE | AFTER |
|---|---|---|---|---|---|
| CrewAI 1.15.26 | A: `kickoff(inputs=...)` | benign_toolcalls corpus | 190 | 65/65 | 0/65 |
| | | discriminator | 50 | 5/5 | 0/5 |
| | | domains | 120 | 21/21 | 0/21 |
| | | sql_dml | 50 | n/a, no destinations | n/a |
| | | FP URL hosts | 2,978 | 2,945/2,945 | 0/2,945 |
| | | FP tokens | 957 | n/a, `connect(address=)` is not destination-shaped | n/a |
| CrewAI | B: no inputs | all | 4,345 | 0/3,036 | 0/3,036 |
| Agents SDK 0.23.1 | A: `await Runner.run`, one `asyncio.run` per case | all | 4,345 | 3,036/3,036 | 0/3,036 |
| | B: `Runner.run_sync` | all | 4,345 | 3,036/3,036 | 0/3,036 |

The Agents SDK reviewer added a long-lived single-loop shape, with all 4,345
requests in one task. It gave identical per-case wires, with no request reading
another's ledger.

**What BEFORE also shows, measured.** These are D2 arguments; D2 removes each one:

- In a mixed CrewAI host, a `kickoff()` with no inputs, or `inputs={}`, after an
  input-bearing request reads the PREVIOUS request's implicit ledger. It got
  `principal_undeclared_span` for a destination it never named.
- An Agents SDK input with no scannable string (`'   '`) does the same. Shapes B
  and the single-loop shape read the previous request's ledger.
- A multi-string input (CrewAI `inputs` with two strings; an Agents SDK message
  list) keeps only the LAST string's destinations, because each input scan
  replaces the implicit ledger (F6, now measured).

**The Agents SDK drivers wrap their tools by hand.** They build a `FunctionTool`
around the `sensor.protect_tools` callable, because the documented tool shape did
not work with this SDK release. That was reported to the owner separately, and is
not A2's.

## 6. Verification from outside the process, per phase

Every phase's outside test builds the wheel from the tree, installs it
`--no-deps` into a fresh venv, and runs the driver with `python -I`. The driver
refuses unless `xaidr.__file__` is in that venv's site-packages
(tests/outside/harness.py).

## 7. Questions for the owner that this build does not decide

- **Q-A.** Should `@xaidr.flow` support `async def` handlers with its own
  `__call__`, rather than refusing them? D1.1 refuses, because `ContextDecorator`
  cannot scope a coroutine body.
- **Q-B.** The observation reported separately (§2.3, last paragraph) gets its
  own branch and release, like the async fix.
- **Q-C.** How should a NESTED hooked run's input be treated? P4 scans it for
  detection and does not record it as principal (§4, P4). That is the safe
  direction: it grants no authority and adds no block. The alternative is to
  record it as an untrusted source, which would block its destinations under
  ENFORCE. The same question applies to explicit host flows today, where the
  nested input IS recorded as principal (read, not run).
- **Q-D.** The Agents SDK tool-shape observation (§5, last paragraph) predates A2.
  Should it get its own branch?
- **Q-E.** A scope opened inside an open scope JOINS it, and its `principal=` is
  not applied (§1). The second review measured that a replacing nested scope
  opens the tier gate in the documented middleware-plus-decorated-handler shape;
  joining is the safe reading of D1. Is it the owner's?
- **Q-H (blocking P2).** D2 changes the conformance contract with paid:
  `tests/value_origin_conformance/convert.py` says that changing an expected row
  "must name the rule that justifies it (and obliges paid ...)". Under D2 the
  supplementary cases R31-implicit-bound, R31-implicit-replaced and
  R31-bind-ledger-noop-on-implicit go red. So do the implicit-bind procedural test
  and seven M9 wheel rows. Does D2 stand with paid obliged to follow?
  P2 (`9d8932c`) is reverted (`61969fb`) until the owner rules, and it re-applies
  cleanly. *Corrected:* §3's SEAMS set (`tests/test_*.py`) skips
  `tests/value_origin_conformance/` and the outside M9 test. The selection for
  every phase must add `tests/value_origin_conformance/` and every
  `tests/outside/test_*_from_the_wheel.py` that a phase's drivers touch.
- **Q-G (blocking P1, and with it P3 and P4).** What should `xaidr.flow()` do
  when it finds request state already in the context? Three designs each
  failed P1's counter-case, because every available rule trades (1) for (2)
  (PROGRESS.md). Options:
  - **(a) Narrow the guarantee.** An OUTERMOST scope isolates its request.
    Nested scopes join only within the same task/thread and only while the
    enclosing entry is live. Keep-evidence covers untiered hops.
    `clear_flow()` never closes an enclosing scope. Generator-held scopes are
    refused at every detectable depth. The undetectable cases are documented
    as the plain pair's limitation, each pinned by a strict xfail whose body
    states its flip condition.
  - **(b) A ledger-only scope.** `flow()` never touches chain, tiers or the
    inbound mark when a flow is already active. It binds a fresh ledger,
    restores the ledger on exit, and seeds a principal chain only when no
    flow is active. That removes counter-case (1) from the scope by
    construction, because tier state stays with `begin_flow` and
    `extract_context`. Counter-case (2) remains for ledgers, with the same
    join-or-fresh choice.
  Either way, P3 (`flow(inbound=)`) and P4 (auto-scope) build on the answer.
- **Q-F.** A scope cannot be opened inside a generator's body (§1). This is
  stricter than D1 says. It is the only design of the three that two reviews
  could not break: a generator's body runs whenever and wherever it is resumed or
  collected.
