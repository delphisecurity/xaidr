# Run-tree capture: design spec (8 Oct sensor build list, item 1)

Status: **built** on branch `feat/run-tree` (2026-10-19), per Ani's rulings:
Q-R1 = M2 (wrap the public `configure` classmethods), D1 = A, D2 = D, D3 = A with
D3b, D4 as proposed. Sections below record the design as written for those
decisions. Where the build proved a statement false, the statement is marked
**[CORRECTED 2026-10-19]** in place rather than silently rewritten. §8 lists what
the build found that this spec did not anticipate.

Base: `0502c99`, which equals `origin/main` as fetched 2026-10-18. Every xaidr
`file:line` below is at that commit. Evidence produced in this loop is in
[`docs/run-tree-evidence/`](run-tree-evidence/): the probe and benchmark scripts,
plus their raw output.

---

## 0. Read first: facts that change how to read this

- **The ground-truth report is not committed anywhere.**
  `experiments/langchain_visibility/REPORT.md` exists only as an untracked file in
  `~/worktrees/opena2a/exp-langchain-visibility` (branch `exp/langchain-visibility`,
  `git status`: `?? experiments/`, plus an uncommitted
  `M xaidr/integrations/langchain.py`). It is not in this repo's history on any
  branch (`git log --all -- 'experiments/langchain_visibility/*'` returns nothing).
  This spec cites it by section (§) rather than by commit, because no commit exists
  to cite. Merging it, or at least the report, would give the citations a stable
  target.
- **The report measured `772be37` (1.20.0). This spec re-reads the code at
  `0502c99`.** The seams it names have not moved. The two commits in between (#39 and
  #40) touch rule assets and docstrings only.
- **Library versions measured:** langchain-core 1.6.8, langchain 1.4.3, langgraph
  1.2.14 (the experiment's `.venv-exp`). CI pins langchain-core 1.6.1, langchain
  1.4.1 and langgraph 1.2.12. **Nothing here was run against the CI pins.**
- **The probe uses a fake chat model, and the inner agent is synchronous.** V4 below
  runs the outer graph with `ainvoke`, but the `create_agent` node inside it calls
  `agent.invoke`. An async `create_agent` was **not** exercised. `d38486a` on
  `feat/value-origin-seams` records that async `create_agent` hosts crash at the
  first tool call under xaidr's middleware (no `awrap_tool_call`). That defect is
  independent of this design, and the build loop must not trip over it.
- **Local `main` is stale** (`60533b8`). Every comparison here is against
  `origin/main`.

---

## 1. What the 8 October experiment established

From REPORT §1, §3 and §7, measured on `START → retrieve_context → support_agent → END`:

- xaidr installs **no callback handler**. The grep for `BaseCallbackHandler`,
  `on_chain_start`, `run_id` and `parent_run_id` over `xaidr/` returns 0 hits
  (§1b). Re-checked at `0502c99`: still 0.
- The experiment's own `BaseCallbackHandler` (`probe.py`) saw **27 runs and
  0 dangling `parent_run_id`** per run, plus `langgraph_node` for every graph node
  (§3). The gateway log held 0 of the 27 run ids. xaidr's log held no node, run-tree,
  retriever, artifact or origin field (§3a, §6).
- In the report's ranked list, item 1 is: *"Install a LangChain callback handler
  from `protect()` that stamps `run_id`, `parent_run_id` and `langgraph_node` on
  every xaidr event, and keys per-flow state by the root `run_id`"*. The report calls
  it the flow key that value origin needs across LangGraph nodes (§7).
- The probe was attached with `config={"callbacks": [Probe(...)]}` on one
  `invoke` call (`run_experiment.py:114`). **`protect()` cannot do that.** It never
  sees the user's `invoke` call. So the attach mechanism is the first open question,
  and §2b answers it.

---

## 2. The real seams and schema today (`0502c99`)

### 2a. How `protect()` installs instrumentation

`protect()` (`xaidr/autopatch/__init__.py:128`) builds one sensor, then runs
`_dispatch` (`:268`). `_dispatch` walks `TARGETS` (`autopatch/frameworks.py:1088`)
and calls each present target's patcher with a `PatchContext`. There are two
sanctioned primitives, both in `autopatch/core.py`:

| Primitive | Where | Contract |
|---|---|---|
| `PatchContext.install(module, dotted, boundary, factory)` | `core.py:229` | Resolves only from `sys.modules` (`:199-212`, rule 1). Idempotent via `PATCH_TOKEN` (`:255-267`). Records undo on the manifest (`:288-289`). Wrappers from `make_wrapper` (`:111`) fail open and log the exception **type only, never the message** (`:134-141`). |
| `PatchContext.install_registry_hook(target, boundary, register)` | `core.py:301` | "Preferred over `install` wherever a framework offers one" (`:314`). `register()` must return an uninstall callable (`:346-352`). Idempotent via `_INSTALLED_REGISTRY_HOOKS` (`:67`). Used by CrewAI (`frameworks.py:705`). |

The LangChain-family seams at `0502c99`:

| Target | Seam | Kind | file:line |
|---|---|---|---|
| `langchain_core` | `BaseTool.run` / `.arun`: argument scan before, `tool_result` scan after | class method | `frameworks.py:321-408` (before `:325-339`, after `:341-380`) |
| `langchain` | `create_agent`: injects `DelphiMiddleware` | module function | `frameworks.py:463-502` |
| (middleware) | `before_model` / `wrap_tool_call` / `after_model` | AgentMiddleware | `integrations/langchain.py:184-295` |
| re-entrancy | `_MW_TOOL_SCANNED` ContextVar suppresses the `BaseTool.run` argument scan under the middleware | ContextVar | `frameworks.py:49`, `:326`, `:443-453` |
| `langgraph` | none; reported `found_unpatchable` | — | `frameworks.py:529-540` |

### 2b. Where a callback handler would attach

There are two mechanisms. **Both were run, and they behave identically on V1–V7
(§3).** Which one to use is question Q-R1 in §5, because the first collides with
`protect()`'s rule 1.

**M1: LangChain's configure-hook registry.**
`langchain_core.tracers.context.register_configure_hook(context_var, inheritable,
handle_class=None, env_var=None)` (`tracers/context.py:171-202` in 1.6.8) appends to
the module-level `_configure_hooks`. Every `CallbackManager` configuration consumes
that list (`callbacks/manager.py:2564-2584`):

```python
for var, inheritable, handler_class, env_var in _configure_hooks:
    ...
    if var.get() is not None or create_one:
        var_handler = var.get() or ...
        if handler_class is None:
            if not any(handler is var_handler for handler in callback_manager.handlers):
                callback_manager.add_handler(var_handler, inheritable)
```

A `ContextVar` created with **`default=handler`** returns the handler from
`var.get()` in every context, including a fresh thread. So
`register_configure_hook(ContextVar("xaidr_run_tree", default=h), inheritable=True)`
puts `h` on every configured manager in the process. It is deduplicated by
identity, and child managers inherit it. Two constraints apply:

- **Rule 1.** `langchain_core.tracers.context` is **not in `sys.modules`** after
  any typical import. `manager.py:2429` imports it lazily, on the first run
  (`docs/run-tree-evidence/rule1_modules.txt`):
  ```
  import langchain_core.tools                {'langchain_core.tracers.context': False, 'langchain_core.runnables.config': False, 'langchain_core.callbacks.manager': False}
  from langchain.agents import create_agent  {'langchain_core.tracers.context': False, 'langchain_core.runnables.config': True, 'langchain_core.callbacks.manager': True}
  import langgraph.graph                     {'langchain_core.tracers.context': False, 'langchain_core.runnables.config': True, 'langchain_core.callbacks.manager': True}
  new modules on importing langchain_core.tracers.context after create_agent: 2
  non-langchain_core: []
  after first Runnable.invoke: tracers.context loaded = True
  ```
  At `protect()` time, M1 therefore requires importing a framework module, and
  `_dispatch` reports that as `RULE 1 VIOLATION` (`autopatch/__init__.py:320-326`).
- **Uninstall is private.** `register_configure_hook` has no inverse. Removing the
  entry means `_configure_hooks.remove(entry)` on a private list.

**M2: wrap the public `configure` classmethods.** `CallbackManager.configure`
(`manager.py:1682-1683`) and `AsyncCallbackManager.configure` (`:2211-2212`) are
public classmethods. The paths I checked route through them:

- `BaseTool.run` / `arun` (`tools/base.py:1047`, `:1175`);
- every Runnable, via `get_callback_manager_for_config` (`runnables/config.py:563-572`).

A wrapper adds the handler to the returned manager if it is absent. The seam is a
class-method seam installed with `ctx.install`, so `PatchContext` already handles
idempotency and undo, and `classmethod` descriptors are preserved
(`core.py:272-277`). M2 needs `langchain_core.callbacks.manager` in `sys.modules`.
That module is present after the `create_agent` and `langgraph` imports and absent
after a bare `import langchain_core.tools` (the same table as above).

**Where the stamp reads from.** The stamp does not need the handler to *push*
anything into the sensor. LangChain keeps the current run's config in
`langchain_core.runnables.config.var_child_runnable_config` (`runnables/config.py:174`).
`set_config_context` (`:224`) sets it for every runnable, and LangGraph copies it
into the thread that runs each node. At any point inside a run,
`var_child_runnable_config.get()["callbacks"].parent_run_id` is the **enclosing
run's id**, and `["metadata"]["langgraph_node"]` / `["langgraph_step"]` name the
innermost graph node. The handler's only job is to map run id to root, parent and
node, because the config does not carry the root.

One consequence fixes what a `tool_call` event can be stamped with. `BaseTool.run`
sets the tool's *own* child config only inside the run
(`tools/base.py:1089-1090`, after `on_tool_start` at `:1073`). xaidr's `BaseTool.run`
wrapper and `wrap_tool_call` both run *outside* that span. So a `tool_call` event
(pre-execution, by design) is stamped with the **enclosing ToolNode run** (`tools`),
never with the tool's own run, which does not exist yet. The join from the event to
the tool's run is `tool_call_id`: `on_tool_start` receives it (`tools/base.py:1080`;
V5 below), and both xaidr tool seams hold it (`integrations/langchain.py:230`,
`frameworks.py:278`).

### 2c. The event schema today

The envelope is `{"type": "scan", "agentId": …, "data": {…}}`. In REPORT §1c,
these 25 `data` keys were seen across both runs:

```
action agentId authzDecision authzPolicyId category chainTiers delegated destinationIdentifier
destinationType direction enforcementMode impactClass impactTier leastPrivilegedTier mcpServer
privilegeTier privilegeTierConfigured promptHash promptLength rules scanId scanTimeMs score
timestamp toolName
```

There are also optional keys: `provenance` (`sensor.py:1866-1867`, `:2767-2768`),
`traceParent` (W3C, `scan` and `scan_a2a` only: `:1868-1869`, `:2134-2135`; tool-call
events never carry it), and `nano*`.

- **No run, node or step field exists.** Content is recorded only as `promptHash`
  + `promptLength` (`sensor.py:1863-1864`, tool call `:2764-2765`).
- **`tool_result` events carry no `toolName`.** The after-hook calls
  `ctx.sensor.scan(text, direction="tool_result")` with no tool name
  (`frameworks.py:367`). This is still true at `0502c99`: every probe `tool_result`
  line in §3 shows `"tool": null`.
- **There are 10 enqueue sites, not one.** `self._telemetry.enqueue(` appears at
  `sensor.py:930, 1265, 1332, 1370, 1662, 1741, 1905, 2136, 2769`, and
  `ProtectedHttpClient` has one more at `:3847`. `SyncTelemetryQueue.enqueue`
  (`telemetry.py:131-139`) runs **on the caller's thread** and only `put_nowait`s,
  then a worker thread flushes. A stamp taken at enqueue time therefore reads the
  caller's context. V2 below confirms this, including on LangGraph's pool threads.
- **Mapping:** `schema.py` maps events to `gen_ai.security.*`, `SCHEMA_VERSION =
  "0.2.0"` (`schema.py:58`). `traceParent` maps to `gen_ai.security.trace.*`
  (`:510`) and provenance to `gen_ai.security.provenance.*` (`:540`).
- **A single funnel exists only on an unmerged branch.** `feat/value-origin-seams`
  adds `DelphiSensor._enqueue_event`, through which "every telemetry event this
  sensor emits passes" (that branch's `sensor.py:2474`), and bumps `SCHEMA_VERSION`
  to `0.3.0` for `valueOrigin`. Whichever of the two builds lands second rebases onto
  the other's funnel. §4.3 assumes that funnel. **[CORRECTED 2026-10-19]** Ani
  ruled that run-tree lands first, so `feat/run-tree` adds `_enqueue_event` and
  routes all 10 sites through it; `feat/value-origin-seams` rebases onto that
  funnel and adds its `valueOrigin` step inside it.

### 2d. The Brain side today (`delphi-sentinel` `origin/main` `01450c7`)

- SDK telemetry is ingested by `runEventsBatch` (`src/events-batch.ts:140`) into
  `ai_guard_logs` (`:348`). It reads **named** `scan.*` fields. A key it never reads
  is discarded silently: the #65 provenance comment (`:196-212`) records that
  `data.provenance` reached 0 of 390 rows because the key was never touched.
- **The rule for join keys is: columns for join keys, jsonb for payload**
  (`:352-355`, citing `migrations/add-provenance-join-keys.sql`). `correlation_id`,
  `parent_scan_id` and `value_origin` are columns. `toolName` and `scanId` live in
  `metadata` jsonb (`:434-437`).
- **`created_at` is ingest time, not event time** (`:251-254`): "The ordering is
  knowable only in the sensor, at emit time."
- **xaidr's `traceParent` has no reader in `events-batch.ts`.** `src/` mentions
  `trace_id` only on the ext_authz path (`scan-pipeline.ts:85-86`, `:514`, `:673`;
  `extauthz-mapper.ts:532`). So the open sensor's `data.traceParent` is dropped at
  this boundary, which is the #65 shape again, live today. The run-tree fields must
  ship with their reader, or they die the same way.
- `src/deps.ts:1716` lists the columns the Brain requires
  (`['ai_guard_logs', 'value_origin', 'migrations/add-value-origin.sql']`). A new
  column joins that list.
- **`ai_guard_logs` has two migration sources.** It is altered both in
  `delphi-sentinel/migrations/` (for example `add-value-origin.sql`) and in
  `blank-canvas/supabase/migrations/` (for example
  `20260211005432_0312f2cf-….sql`). A migration for it must read both.
- **The Brain has two producers.** `parentScanId` comes from `delphi-python-sdk`,
  the paid SDK, via a ContextVar (`xaidr/provenance_chain.py:94` in that repo).
  It does not come from this repo. Whether that ContextVar survives LangGraph's
  node boundary was **not measured**. The value-origin finding in §2e suggests it
  does not.

### 2e. Value origin: the consumer this key exists for

- The ledger is held in a ContextVar and bound once at flow entry
  (`value_origin/_ledger.py:120`, `:131-147`).
- `value_origin/__init__.py:8-12`: `__all__` is pinned for paid. It deliberately
  has no "function that takes a correlation id — each is a laundering or disclosure
  primitive."
- `d38486a` (M10 on `feat/value-origin-seams`, measured from the built wheel at CI
  pins): *"Without it, the DEFAULT LangGraph path, value origin is INERT: each
  before_model binds a node-local ledger the tools node never sees, so the send reads
  no_flow and runs under ENFORCE."*
- That branch's `xaidr.flow()` carries a ledger across with `ledger_get` /
  `ledger_set` (`value_origin/_ledger.py:175-184` there). They are private and kept
  out of `__all__` (`dbdf9b5`). The A2 build is **STOPPED** (`436e6cc`).

---

## 3. Measured: what a handler sees at the enqueue seam

`docs/run-tree-evidence/seam_probe.py` runs the real `xaidr.protect()` **from this
tree** (`xaidr from: /Users/anirudhkotaru/worktrees/xaidr/run-tree/xaidr/__init__.py`;
`PYTHONPATH` set, because the venv holds an editable xaidr from a different
worktree). It replaces `sensor._telemetry.enqueue` with a function that reads
`var_child_runnable_config` and the handler's map, then forwards the event. The
graph has the report's shape: a retriever node, then a `create_agent` node (looked
up after `protect()`, so it is the patched one) with two tools. No network. Full
output: `seam_probe_output_hook.txt` (M1) and `seam_probe_output_patch.txt` (M2).

| # | Question | Result (identical under M1 and M2) |
|---|---|---|
| V1 | Does the handler receive callbacks on a plain `graph.invoke()` with **no** `config=`, run on a fresh thread? | Yes. It saw 21 callbacks (21 runs) per invoke. |
| V2 | At enqueue, do events carry an enclosing run, a node, and a root? | 8 of 8 events got an enclosing run that the handler knew, a node (`DelphiMiddleware.before_model`, `tools`, `DelphiMiddleware.after_model`), a step, and **one** root (`LangGraph`, 3 hops up). The `tool_call` and `tool_result` events ran on `ThreadPoolExecutor-*` threads and were stamped correctly. |
| V3 | Direct `tool.run()` outside any runnable? | `var_child_runnable_config` is `None`, so 0 of 2 events had anything to key on. (LangChain still makes that tool run its own root, but only *inside* `run`, after the pre-execution event.) |
| V4 | Outer graph on `ainvoke`? | Same as V2: 8 of 8 stamped, one root. |
| V5 | Does `on_tool_start` carry `tool_call_id`? | Yes: `{'…66d4': 'call_1', '…278a': 'call_2'}`. |
| V6 | Stamp cost (prototype: config read + root walk) | Median 1.3–1.8 µs, max 6.0 µs, over 68 events. |
| V7 | Two flows on two threads at once, 5 invokes each | 10 roots for 10 invokes. 0 roots mixed both flows' tools. 0 `tool_call` events lacked a root. |

An excerpt (`seam_probe_output_hook.txt`; ids are UUIDv7, so the probe prints the
*tail*, since the head is a timestamp shared by every run in the same second):

```
{"dir": "tool_call", "tool": "lookup_customer", "enclosing": "c4bd1cbd0fe0", "enclosing_known_to_handler": true, "enclosing_name": "tools", "root_name": "LangGraph", "node": "tools", "step": 4, "root": "c81801a90fb5", "hops": 3, "thread": "ThreadPoolExecutor-3_0"}
{"dir": "tool_result", "tool": null, "enclosing": "c4bd1cbd0fe0", "enclosing_known_to_handler": true, "enclosing_name": "tools", "root_name": "LangGraph", "node": "tools", "step": 4, "root": "c81801a90fb5", "hops": 3, "thread": "ThreadPoolExecutor-3_0"}
nodes seen by handler: ['DelphiMiddleware.after_model', 'DelphiMiddleware.before_model', 'model', 'retrieve_context', 'support_agent', 'tools']
```

What this shows:

- `langgraph_node` from the config names the **innermost** node only (`tools`,
  inside the `create_agent` subgraph). The outer node `support_agent` is reachable
  only through the handler's ancestry. The 3-hop chain is
  `tools` run → inner `LangGraph` → `support_agent` → outer `LangGraph`. That chain
  is inferred from `hops: 3` plus the handler's node set: the probe did not print
  the path itself.
- `retrieve_context` and its retriever run produced **zero** sensor events. The
  handler saw them, but no xaidr seam scans retrieval (REPORT D4 and item 2). The
  run tree has the node, and the event stream has nothing to stamp. This is the case
  for D3 option C later.

**I first misread V2** (my error, not the system's). The first run printed the
*head* of each id, and every id looked identical because UUIDv7 heads are
timestamps. The rerun prints tails, and the table above uses the rerun.

---

## 4. Design

### 4.1 Components

1. **`RunTreeHandler(BaseCallbackHandler)`.** Maintains the index below from
   callbacks. Class attributes: `run_inline = True`, so on an async manager it runs
   inline rather than through the `run_in_executor` hop at `manager.py:416-421`; and
   `raise_error = False`, the default.
2. **`RunTreeIndex`.** Bounded, process-local state. For each **live** run it keeps
   `run_id → (root_id, parent_id, node, node_path)`. For each live root it keeps
   `root_id → seq counter`. It holds no content: only ids, node names and integers.
3. **`stamp(data)`.** The read side, called once per event from the enqueue funnel.
4. **The install.** A new `FrameworkTarget`, so the manifest reports run-tree
   capture as its own line, separate from tool scanning. The detection key is
   `langchain_core.callbacks.manager` for M2, or `langchain_core.tracers.context`
   for M1 (Q-R1).

### 4.2 The handler

| Callback | Action |
|---|---|
| `on_chain_start`, `on_chat_model_start`, `on_llm_start`, `on_tool_start`, `on_retriever_start` | `root = index[parent].root if parent else run_id`; `node_path = parent.node_path + (node,)` when `metadata["langgraph_node"]` changes, bounded; insert. A start with `parent_run_id is None` whose `run_id` is already a live root is recorded as a **collision** (§4.5). |
| `on_*_end`, `on_*_error` | Delete that run's entry. When the run is a root, also delete its seq counter. |

The root is computed **at start**, from the parent's entry, so a stamp is an O(1)
lookup and never walks the tree. The prototype walked the tree. Entries are deleted
at each run's own end, so memory tracks **live** runs, not runs per root. A run
whose end never fires (an abandoned generator, a killed thread) is reclaimed by the
cap (§4.6). `tool_result` events are stamped after the tool run ends, but their
enclosing run is the `tools` node, which is still live (V2), so deleting at end does
not lose them.

### 4.3 The stamp

Called from the single enqueue funnel (`_enqueue_event` per §2c), after `data` is
fully built:

```
cfg      = sys.modules["langchain_core.runnables.config"].var_child_runnable_config.get()
cb       = cfg.get("callbacks") if cfg else None
enclosing= getattr(cb, "parent_run_id", None)        # a list here -> no manager -> no_run
entry    = index.get(enclosing)                       # None -> unknown_run
data.update(runTree=..., runRootId=..., runTaskId=enclosing, runParentId=entry.parent,
            runNode=..., runNodePath=..., runStep=meta.get("langgraph_step"),
            runSeq=index.next_seq(entry.root), runSource="langchain")
```

It runs **after** the verdict and the `data` dict exist. It only adds keys. It never
reads or changes `action`, `score` or any verdict field.

### 4.4 The added fields (pending D3)

The brief asks for a "task id, the parent step, and the graph node … keyed to the
root run id". In this design, the **task** is the run executing when the event was
emitted, and the **key** is the root. If "task id" meant the flow, that field is
`runRootId`.

| Field | Type | Meaning | Present when |
|---|---|---|---|
| `runTree` | str | status: `stamped` · `no_run` · `unknown_run` · `collision` · `fault` | the handler is installed (absent means an older sensor or not installed) |
| `runRootId` | str (UUID) | root run of the flow. **The flow key.** | `stamped` |
| `runTaskId` | str (UUID) | the run executing at emit time (for `tool_call`, the ToolNode run; see §2b) | `stamped` |
| `runParentId` | str (UUID) \| absent | the parent of `runTaskId` (the "parent step") | `stamped`, non-root task |
| `runNode` | str (≤128 chars) | innermost `langgraph_node` | inside a LangGraph node |
| `runNodePath` | list[str] (≤8) | node names from root to leaf, e.g. `["support_agent", "tools"]` | inside a LangGraph node |
| `runStep` | int | `langgraph_step` | inside a LangGraph node |
| `runSeq` | int | per-root counter assigned at stamp time. It is the in-flow order, which the Brain cannot recover (`created_at` is ingest time, §2d) | `stamped` |
| `runSource` | str | `"langchain"`; the provider name, so that D1 can widen without renaming fields | `stamped` |
| `toolCallId` | str | LangChain's `tool_call_id`, on `tool_call` and `tool_result` events. Joins both to the tool's own run (V5) and gives `tool_result` the attribution it lacks today (§2c) | D3b, needs a seam change |

The field names are deliberately framework-neutral (`run*`, not `langgraph*`), so
the wire shape does not change if D1 widens. `schema.py` maps them to
`gen_ai.security.run.*`.

### 4.5 Degradation: never an error

| Situation | Result |
|---|---|
| LangChain is not imported, or the attach module is not in `sys.modules` | The target is `not_present`, or `found_unpatchable` with "call `protect()` again after importing your graph". No `run*` keys on any event. |
| An unrecognised `configure` shape (not a classmethod, moved) | `PatchUnavailable` → `found_unpatchable`, loud, as every other seam. No keys. |
| An event outside any runnable (direct SDK call, direct `tool.run`: V3) | `runTree: "no_run"`. No ids (D2). **[CORRECTED 2026-10-19]** Exact only from Python 3.11. Before 3.11 a missing run config does not establish "outside any run" (§8), so while any run is live such an event reports `unknown_run`. Still no ids. |
| The enclosing run is not in the index (started before `protect()`, or evicted by the cap) | `runTree: "unknown_run"`. No ids. **Never** a guessed root (see below). |
| Two roots share a `run_id` (a user-supplied `config["run_id"]` reused while live) | `runTree: "collision"`. No ids for either until both end. **[CORRECTED 2026-10-19] "until both end" was the wrong rule, and the first build implemented it.** A fresh-context review showed two merges against real LangChain. (1) A reused CHILD id marked only the newcomer's root collided, so the first flow kept `stamped` and both flows shared its root. (2) Once the first flow ended, the collided flag went with it, and a third flow reusing the id was stamped while the second was still live. The rule now: a run id is a flow key only the first time it is seen. Any reuse (live, recently ended or evicted, already collided; root or child) taints the id and marks every root it touches, and a tainted id resolves to `collision` from then on (§8). |
| Any exception in the handler or the stamp | Swallowed. A fault counter is incremented, the exception **type** is logged once, the event gets `runTree: "fault"`, and the event is otherwise emitted unchanged. |

There is a direction to the risk, and the table follows it. A **split** flow (one
flow under two roots, for example a user node that starts a thread without copying
context, so the inner agent becomes a new root) costs the Brain a join. It costs
value origin a lookup, which fails toward "unresolved". A **merged** flow (two flows
under one root) lets one flow's principal input vouch for another flow's call, which
is laundering. Every ambiguous case above therefore resolves to *no key*, never to
the nearest plausible root.

### 4.6 Bounds

| Bound | Value | Why |
|---|---|---|
| Live-run index | cap 4096 entries; past it, evict the oldest root and everything under it | an end that never fires must not leak. Measured with no eviction: 1100 entries after 100 invokes, about 84 KB attributed to a 2-field entry (`bench_handler_output.txt`), growing without bound |
| `runNodePath` | ≤ 8 names | nesting deeper than 8 subgraphs is truncated from the root side and marked |
| Node names | ≤ 128 chars each | node names are user-supplied strings |
| Ids | `str(uuid)`; anything else is rejected → `unknown_run` | `run_id` is user-suppliable |
| Per-callback work | O(1): one dict read and one insert, under a lock | — **[CORRECTED 2026-10-19]** Except a root's end or eviction, which is linear in the runs still filed under that root, so bounded by the cap. |
| Per-stamp work | O(1): one ContextVar read, one dict read, one counter increment | — |

### 4.7 Install, uninstall, idempotency

These follow the four `protect()` rules (`autopatch/__init__.py:9-24`):

- one handler per `protect()` sensor;
- M2 installs through `ctx.install`, so the token makes a second `protect()` report
  `already_patched`;
- M1 installs through `ctx.install_registry_hook`, with uninstall =
  `_configure_hooks.remove(entry)` plus a handler-level `active = False`, so a failed
  removal leaves an inert handler rather than a live one;
- `unprotect()` reverses it, and the index is dropped.

### 4.8 How the Brain consumes it

1. **The reader, in the same PR as the producer.** `events-batch.ts` reads each
   `run*` key **by name**, beside `parentScanId` / `valueOrigin` (`:259`, `:270`).
   `traceParent` (§2d) is the live counter-example: emitted, never read, gone.
2. **The column, for the join key only.** A `run_root_id text` column on
   `ai_guard_logs`, with a partial index `(deployment_id, run_root_id, created_at
   desc) where run_root_id is not null`. That is the `add-provenance-join-keys.sql`
   rule. The other keys go into `metadata` jsonb. A key gets promoted to a column
   when something joins on it. The migration lands in `delphi-sentinel/migrations/`
   after reading `blank-canvas/supabase/migrations/` (two sources, §2d). The column
   is added to `deps.ts:1716`.
3. **What it enables:**
   - *one flow's events, in order*: `where run_root_id = $1 order by
     (metadata->>'runSeq')::int`;
   - *interleaved flows told apart*, which is REPORT §3c row 2: a ticket read in flow
     1 cannot be confused with a note written in flow 2;
   - *which graph node emitted a tool call* (`metadata->>'runNode'`);
   - with D3b, `tool_result` attributed to its `tool_call` row through `toolCallId`.
4. **Verifying from outside.** The deployed Brain's `/health` returns its commit.
   A claim that the Brain stores `run_root_id` is verified by that commit **and** by
   an operator-run SQL count. It is not verified by CI (CLAUDE.md, completion
   clause 3). The value-origin precedent applies: the Brain deployed on 2026-10-06
   did not read `valueOrigin` at all (seams branch `sensor.py:2491-2493`).

### 4.9 How value origin (item 3) uses it, in process and not over the wire

The ledger stays keyless. `value_origin/__init__.py:8-12` forbids a function that
takes a correlation id, and this design does not add one. Instead, the **seam
layer** keeps `root_id → ledger` beside `RunTreeIndex`, with the same lifetime: it
is created at root start and dropped at root end. Before each seam calls
`record_*` or `evaluate_call`, it binds the root's ledger, using the private
`ledger_get` / `ledger_set` that `feat/value-origin-seams` already added for
`xaidr.flow()`. This removes M10's "node-local ledger the tools node never sees"
without changing `__all__`. `collision` and `unknown_run` bind **no** ledger, and
that is the merge-safety rule from §4.5 applied to item 3. **None of this is
built or measured.** It shows that the key is sufficient. It does not show that
the binding works.

### 4.10 Out of scope

- No retriever scan (item 2).
- No artifact scan (item 4).
- No new verdict, and no change to any existing verdict.
- No `awrap_tool_call` (§0).
- No change to `tool_result`'s missing `toolName`, unless D3b is taken.
- No OTel span export. `trace_context.py:15-21` keeps the sensor a reader only, and
  this design does the same.

---

## 5. Decisions for Ani

Each decision gives the options, a recommendation, and what would change the
recommendation. None of them is decided here.

### Q-R1 (raised by the read, not in the brief): attach mechanism vs. rule 1

| Option | For | Against |
|---|---|---|
| **M1 registry** + a named rule-1 exception for `langchain_core.tracers.context`, granted only when `langchain_core.callbacks.manager` is already loaded | It is LangChain's sanctioned hook. `core.py:314` prefers registries. The import adds 2 langchain_core modules, and LangChain imports the same module itself on the first invoke (`rule1_modules.txt`). | It breaks rule 1 as written. The dispatcher's `RULE 1 VIOLATION` check would need an allowlist. Uninstall relies on a private list. |
| **M2 classmethod wrap** of `CallbackManager.configure` / `AsyncCallbackManager.configure` | Rule 1 stays intact. The name is public and documented. Undo and idempotency come from `ctx.install` for free. Measured identical to M1 on V1–V7. | A patch is "a bet that a private call path will not move" (`core.py:315`). The CrewAI patch went dead this way (`frameworks.py:660-671`). Here the bet is on internal callers continuing to use `configure`, which is a public entry point and not a private path. |

**Recommendation: M2.** It keeps rule 1 intact with no exception. The coverage risk
it carries can be measured: the build's real-framework test asserts that the handler
saw a run for every `BaseTool.run` and node, so a LangChain release that routes
around `configure` turns a test red instead of going silently dead. **What would
change it:** a LangChain path that configures callbacks without going through
`configure`, found by that test.

### D1: scope

| Option | Description |
|---|---|
| **A** | LangChain/LangGraph only in v1. Every other framework seam degrades to "no `run*` keys". Field names are neutral, and `runSource` names the provider (§4.4). Internally, `current_run()` dispatches through a registry keyed by provider, like the canonicalizer's `_NORMALIZERS` (`feat/action-canonicalization` `canonicalize.py`), with one provider. |
| **B** | A generic run-tree abstraction across all seams now: OpenAI Agents SDK, CrewAI, LlamaIndex, AutoGen (two lines), Haystack, MCP. |

**Recommendation: A.**

- The only run-tree measurement anyone has made is LangChain's (REPORT §3, and V1–V7
  here).
- Each other framework has its own run model, and **none of them was read in this
  loop.** I did not open their tracing APIs, so I make no claim about what they
  expose.
- An abstraction shaped from one instance is a guess about the others, and this
  codebase has paid for one such guess already: the CrewAI `BaseTool.run` patch
  reported coverage on 0 of 3 agent paths (`frameworks.py:660-671`).
- The fleet's framework mix is unknown (REPORT §6).

Neutral field names plus the provider registry mean that widening later changes
nothing on the wire. **What would change it:** a fleet inventory that shows a
non-LangChain framework in production use. That framework becomes provider 2, with
its own measurement first.

### D2: keying when there is no framework run id

| Option | Description | Problem |
|---|---|---|
| A | Synthesize a root per event | No two events share it, so the key joins nothing. |
| B | Synthesize a root per thread or per ContextVar scope | Thread-reusing servers carry it across requests. value_origin names this exact failure (V-27, `_ledger.py:18`). `trace_context.py:19-21` deliberately refuses a self-owned parent stack. |
| C | Copy a host-declared flow key (`begin_flow` correlation id, `traceParent.traceId`) into `runRootId` | It conflates two key spaces in one column. The Brain already stores `correlation_id` in its own column (§2d). |
| **D** | Leave the event unkeyed: `runTree: "no_run"`, no ids | — |

**Recommendation: D.**

- The run-tree key means "LangChain told us this run's ancestry". Every synthesized
  key is a guess wearing that meaning. `schema.py`'s own rule is "Missing fields are
  OMITTED, never guessed".
- Non-framework flows already have explicit, host-declared keys. `begin_flow`'s
  `correlation_id` is read by the Brain into `ai_guard_logs.correlation_id`.
  `traceParent` is carried too, but has no Brain reader yet (§2d). The Brain can
  coalesce them, and the sensor should not merge them.
- The cost is named, not hidden. For item 3, an unkeyed direct-SDK flow is
  `no_flow` in value origin, which `d38486a` shows runs under ENFORCE. The remedy for
  those hosts is explicit `begin_flow` / `xaidr.flow()`, which is item 3's ruling
  to make, not this one's.

**What would change it:** a ruling that value origin must cover flows with no
declared scope. That is a value-origin decision, with V-27 as the counter-case it
must answer.

### D3: the fields, and whether they ride the existing event or a new envelope

| Option | Description | Assessment |
|---|---|---|
| **A** | Flat top-level `run*` keys on the existing `scan` event (§4.4) | Matches how `parentScanId`, `evaluatorGeneration` and `valueOrigin` ride today: top-level, "minted by the sensor's scan-emit path" (`events-batch.ts:256-270`). The Brain reads them by name. One column, `run_root_id`. |
| B | A nested `data.runTree = {…}` object | This is the `provenance` shape: a nested block that reached 0 of 390 rows because the Brain never read its key (#65). It also implies a single producer. |
| C | A new envelope `{"type": "run", …}` for run start and end, with scans carrying only the key | Gives the Brain the whole tree, including runs that emit no scan (`retrieve_context`, V2). But today's Brain drops any event without a `scanId` (`events-batch.ts:190`), volume roughly doubles or triples (21 callbacks against 8 scan events per invoke here), and a new type is a breaking addition for consumers (the reasoning in `schema.py:36-57`). |

Sub-decisions:

- **D3b: `toolCallId` on `tool_call` and `tool_result`.** This needs the two tool
  seams to pass `tool_call_id`, which they already hold, into the scan call. It is
  the only field here that is not a pure stamp.
- **D3c: storage.** `run_root_id` as a column. The rest in `metadata`.

**Recommendation: A, D3b yes, D3c as stated.**

- A is the shape that has demonstrably survived the Brain boundary, and it is
  enough for item 3. Item 3 needs the key **in process** (§4.9), not on the wire.
  The wire copy is for the Brain's joins.
- D3b closes REPORT D3 (unattributed `tool_result`) at its cause, for the price of
  one argument.
- Defer C to item 2. Once retrieval emits its own events, the runs that today emit
  nothing will have something to carry, and the event type can be designed against
  real cases.
- Coordinate the `SCHEMA_VERSION` bump with `feat/value-origin-seams` (`0.3.0`
  there), whichever lands first. **[CORRECTED 2026-10-19] False: there is no bump
  to coordinate.** This repo's rule, pinned by
  `tests/test_audit_f9_tool_telemetry.py::test_schema_version_did_not_move_for_this_change`,
  is that additive keys do not move `SCHEMA_VERSION` and a changed meaning does.
  The `run*` keys and `gen_ai.tool.call.id` are additive, so run-tree keeps
  `0.2.0`. Whether `valueOrigin` moves it is that branch's own question.

**What would change it:** a Brain consumer that needs runs with no scan event in v1.
That is C, built together with item 2.

### D4: overhead and safety budget

Proposed ceilings, against what was measured:

| Quantity | Proposed ceiling | Measured (prototype, this machine) |
|---|---|---|
| Stamp, per event | **≤ 10 µs p99** | median 1.3–1.8 µs, max 6.0 µs, over 68 events (V6). That is about 0.3–0.4% of the median scan (0.43 ms, `docs/performance.md:10`). |
| Handler, per callback | **≤ 10 µs p99** | Below this benchmark's resolution. 5 of 7 runs fell between +0.4% and +2.3% of a ~1.4 ms invoke at 11 callbacks per invoke (≤ ~3 µs per callback). The outliers were −7.1% and +9.9%, at load average ~7.8 (`bench_handler_output.txt`). A quieter machine or more rounds is needed to resolve it. |
| Memory | **≤ 2 MB** at the 4096-entry cap | ~76 B per entry for a 2-field prototype entry. The design's 4-field entry is not measured, and the 2 MB figure is an estimate. **[CORRECTED 2026-10-19] Measured on the build:** about 1.4 MB retained at the cap after 50k flows, a third of them abandoned (`test_d4_budget_index_stays_under_2mb_with_many_flows`). **[CORRECTED AGAIN 2026-10-19] That figure undercounted.** It counted only allocations made in `run_tree.py`, which left out the UUIDs and node names only the index kept alive. Counted across all files, the same workload was 1.94 MB, and a root-only abandoned workload was 2.52 MB, over budget. The index now keys by `uuid.int` and keeps root state on the root's own entry. The gate counts every file over three workloads: mixed 1759 KiB, root-only abandoned 1248 KiB, reuse storm 752 KiB (`docs/run-tree-evidence/implementation/budget_runs.txt`). |
| Per-callback and per-stamp work | O(1), no tree walk (§4.2) | the prototype walked the tree (≤ 3 hops here) |

The guarantees, stated against the canonicalizer's contract
(`feat/action-canonicalization` `canonicalize.py:22-30`):

- **Never raises.** It matches the canonicalizer, and it is stricter than leaning on
  LangChain. LangChain does catch handler exceptions, but logs them as
  `logger.warning("Error in %s.%s callback: %s", …, repr(e))` (`manager.py:341-346`),
  and a `repr` can carry content. xaidr's own wrappers refuse to log messages for
  exactly that reason (`core.py:134-141`). So every handler method and the stamp
  catch internally, log the **type** once, and count.
- **Bounded.** It matches: §4.6.
- **Pure.** It **cannot** match. The index is state by definition. The containment
  is that the state is process-local, capped, holds no content (ids, node names and
  integers only), is mutated only by callbacks, and is never read by any verdict path.
- **Additive to the verdict.** It is stricter: the stamp is outside the verdict
  entirely. It runs after `data` is built, adds keys, and cannot raise a verdict or
  lower one.
- **No I/O, and no imports at run time.** Modules are resolved from `sys.modules`.
- **Concurrency.** Index mutations happen under a lock, and reads are lock-free
  `dict.get`. V7 covered two threads. Free-threaded CPython (3.13t) was **not**
  tested.

**Recommendation:** adopt the ceilings above, and enforce them the way
`docs/performance.md` enforces its scan ceiling: a test asserts the ceiling, not the
measured value. Then the ceiling has headroom, and a regression past it is caught.
Budget the handler at 10 µs even though it measured lower, because this benchmark
cannot resolve it. **What would change it:** a CI-pinned, quiet-machine measurement
showing the handler above 10 µs per callback. That would point at the lock, and the
fix would be a lock-free index for inserts.

---

## 6. What the build loop must prove

Changing what every event carries alters what a running system does. So this is a
milestone, and each test below needs its failing-first proof (CLAUDE.md,
§Completion).

| Test | Red against | Asserts |
|---|---|---|
| T1 | `0502c99` (no `runRootId` key) | every event emitted inside a `create_agent`-in-`StateGraph` run carries `runTree: "stamped"`, and every event from one invoke carries the same `runRootId` |
| T2 | a sabotaged index that keys by thread | V7 as an assertion: two concurrent flows never share a root |
| T3 | a handler that raises in `on_chain_start` | the host graph completes, events carry `runTree: "fault"`, and no log record contains the exception message |
| T4 | eviction removed | 10k abandoned roots leave the index ≤ cap |
| T5 | — | direct `tool.run()` → `no_run`; LangChain absent → no `run*` keys and a manifest line; `protect()` twice → `already_patched`; `unprotect()` → no handler on new managers |
| T6 | Q-R1 coverage | every `on_tool_start` and every node seen by a reference `config=` probe is also seen by the installed handler (catches a `configure` bypass) |
| T7 | `tool_result` without `toolCallId` (if D3b) | a `tool_result` event joins to its `tool_call` event by `toolCallId` |

Run them from the **built wheel** at the **CI pins**: the `real-frameworks` job tests
the tree, not the wheel. Run the async `create_agent` cases once `awrap_tool_call`
exists (§0). The outside-the-process check is the Brain's: a stamped batch posted to
`/v1/events/batch` on a Brain whose `/health` commit includes the reader, followed
by an operator-run SQL count of `run_root_id`. That check is **deferred** until the
reader and migration exist, and it should be recorded as deferred rather than
skipped.

---

## 7. Not measured, and open

- **The CI pins** (langchain-core 1.6.1 and friends): neither M1 nor M2 was run there.
  **[CORRECTED 2026-10-19]** M2 is now run there, on Python 3.12 and 3.10. CI runs
  the tree; a run from the built wheel was done by hand, and its output is in
  `docs/run-tree-evidence/implementation/wheel_pins.txt` (§8).
- **An async `create_agent`, streaming, and `Send`/map-reduce fan-out:** not
  exercised. **[CORRECTED 2026-10-19]** An async `create_agent` is now exercised
  (§8). Streaming and `Send` fan-out are still not. A `Send` fan-out runs several node tasks under one parent at the same
  step. The design stamps each with its own task run, but that is not measured.
- **The outer-node path** (`runNodePath`) is inferred from the hop count, not
  printed (§3).
- **The LangGraph `thread_id` (multi-turn) versus the root run (one turn).** This
  design keys per turn. Whether value origin's flow should span turns is item 3's
  question.
- **Whether the paid SDK's `parentScanId` ContextVar survives LangGraph's node
  boundary** (§2d): not measured.
- **The handler's per-callback cost:** below this benchmark's resolution (D4).

---

## 8. What the build found (2026-10-19)

- **Python < 3.11 cannot place async events.** LangChain sets the run config in a
  copied context and hands it to async code only through
  `asyncio.create_task(context=...)`, which Python added in 3.11
  (`langchain_core.runnables.utils.asyncio_accepts_context`). On 3.10 the handler
  still sees every run, but an async node (and any sync tool it dispatches to an
  executor thread) runs without the config. Those events report `unknown_run`,
  never `no_run` and never a root (`_unplaceable` in `xaidr/run_tree.py`; asserted by
  `test_py310_async_events_are_unplaceable_never_rooted`, run by the new
  `run-tree-py310` CI job). The async legs are strict-xfail below 3.11.
- **An async `create_agent` under the injected middleware crashes at the first tool
  call**, at the CI pins and at the latest versions alike:
  `NotImplementedError: Asynchronous implementation of awrap_tool_call is not
  available`. This predates run-tree (`d38486a`). It is pinned as a strict xfail
  (`test_async_create_agent_with_injected_middleware_is_stamped`) that turns red
  once `awrap_tool_call` lands. An async `create_agent` bound before `protect()`
  (no middleware) runs, and is stamped.
- **The stamp is activated through `install_registry_hook("xaidr.run_tree", …)`,**
  not a bare teardown, so the manifest keeps one restored entry per patched record
  (`tests/test_protect_manifest.py` pins that invariant).
- **`toolCallId` rides a ContextVar** that the two tool seams bind around their
  scan call (`run_tree.bind_tool_call_id`). No public scan signature changed.
- **`toolCallId` is unique only within a flow.** In the outside-the-process run,
  two concurrent flows both produced `call_1`. The join from a `tool_result` to
  its `tool_call` is therefore on `(runRootId, toolCallId)`, never on
  `toolCallId` alone.
- **Run-id reuse merged flows in the first build; a fresh-context review found
  it.** See the correction in §4.5. Both orderings are now asserted against real
  LangChain (`test_t2_a_reused_child_run_id_in_two_concurrent_flows_never_merges`,
  `test_t2_a_collided_root_id_stays_collided_after_the_first_flow_ends`) and,
  deterministically, at the index level for every ordering the review named
  (`test_t2_index_*`). One limit remains: the memo of ended ids is bounded, so
  a reuse that comes after the memo has rotated past it is treated as a fresh
  id.
- **A handler attached before `unprotect()` keeps receiving callbacks** for runs
  already in flight. It now does nothing while the stamp is inactive
  (`test_t5_unprotect_stops_indexing_runs_already_in_flight`).
- **`no_run` means "no run config reached the emit point"**, not strictly
  "outside every run". From 3.11 a thread the host starts without copying its
  context also reports it. It still carries no ids.

