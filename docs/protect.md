# Drop-in protection

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

## Drop-in protection

If you would rather not place scan calls by hand, three wrappers do it for you —
or one call wires all three for you.

### One line: `xaidr.protect()`

```python
import httpx, langchain_core.tools          # import your frameworks FIRST
import xaidr

print(xaidr.protect(agent_id="support-agent", enforcement_mode="block"))
```

`protect()` looks at what this process has **already imported**, instruments
every boundary it can reach with one shared `Sensor`, and returns a manifest:

```
xaidr.protect() manifest — agent_id='support-agent' mode='block'
  PRESENT BUT NOT PATCHED (1) — THESE BOUNDARIES ARE UNPROTECTED
    x langgraph        langgraph.graph.StateGraph  [input+output]
        a StateGraph's nodes are callables YOU supply; there is no library-owned
        call site between the graph and your node functions to wrap. ...
  PATCHED (3)
    + httpx            httpx.Client.send  [egress]
    + langchain_core   langchain_core.tools.BaseTool.run  [tool]
    + langchain_core   langchain_core.tools.BaseTool.arun  [tool]
  NOT PRESENT (9) — not in sys.modules, nothing to patch
    - autogen-core, autogen-legacy, crewai, deepagents, langchain, llama-index, ...
```

The manifest is also a mapping (`manifest["patched"]`, `manifest.to_dict()`) and
the reversal handle (`manifest.unprotect()`). Four rules govern it:

| Rule | What it means |
|---|---|
| **Patches only what is in `sys.modules`** | `protect()` never imports a framework to instrument it. That is what keeps `pip install xaidr` a zero-dependency install. |
| **Explicit call only** | Importing `xaidr` patches nothing. There is no import hook and no `.pth` magic — a control with no call site cannot be audited. |
| **Loud about gaps** | A framework that is present but *not* patched raises `XaidrProtectionWarning`, prints to stderr, and heads the manifest. Silence about an unprotected boundary is the one outcome ruled out. |
| **Idempotent** | A second `protect()` reports each site as `already_patched` rather than double-wrapping — which makes "call it again after importing more" a supported workflow. |

**Coverage today**, and where each one enforces:

| Framework | Patch site | Boundaries |
|---|---|---|
| `httpx` | `Client.send`, `AsyncClient.send` | destination policy (every verb), request body, response DLP |
| `requests` | `Session.send` | same |
| `langchain-core` | `BaseTool.run` / `.arun` | tool — also covers LangGraph's `ToolNode` and bare tool calls |
| `langgraph` | *(none — no seam of its own)* | tool only, transitively via `langchain-core`. Graph input/output: **not covered** |
| `deepagents` | *(none — no seam of its own)* | input + output + tool **iff `protect()` ran before `import deepagents`**; otherwise tool only |
| `langchain` | `agents.create_agent` | input + output + tool, via `delphi_middleware` injection |
| `openai-agents` | `Runner.run` / `.run_sync` | input + output |
| `crewai` | `hooks.register_before_tool_call_hook` (a **hook**, not a patch), `Crew.kickoff` | agent-driven tool calls + crew input |
| `autogen-core` / `autogen` | `BaseTool.run_json`, `ConversableAgent.execute_function` | tool |
| `llama-index` | `FunctionTool.call` / `.acall` | tool |
| `mcp` | `ClientSession.call_tool` | tool arguments + the server's returned content |
| `haystack` | `components.agents.agent.Agent.__init__` | input + output + tool, via `delphi_hooks` injection. **Agents built *before* `protect()` are not covered** — a constructor seam cannot reach an object that already exists |

**Known limits, in the manifest rather than the footnotes.** A framework
imported *after* `protect()` is not patched — call `protect()` again. A
module-function seam (`create_agent`) does not reach a name already bound by
`from langchain.agents import create_agent`; a class-method seam (everything
else) does. LangGraph's own graph boundary, the OpenAI Agents SDK's per-instance
`FunctionTool.on_invoke_tool`, and LlamaIndex's non-`FunctionTool` types have no
patchable call site — each is reported as `found_unpatchable` with the reason and
the manual alternative (`sensor.protect_tools(...)`).

**LangGraph was assumed covered; here is what is measured.** `create_agent` had
been proven and a hand-written `StateGraph` had not, so both halves of the claim
are now pinned in `tests/test_real_frameworks.py::TestRealLangGraph` against
langgraph 1.2.11 / langchain-core 1.6.1.

* **Tool calls are covered, and the refusal is readable.** A destructive call
  under `protect(enforcement_mode="block")` executes **zero** times and comes
  back as a `[BLOCKED]` `ToolMessage` with `status="error"`, on `invoke` and
  `ainvoke` alike. It did not always: `BaseTool.run` returned the refusal as a
  *string*, which is what `tool.run(args)` callers are promised but not what a
  `ToolNode` is — ToolNode raises `TypeError: Tool <name> returned unexpected
  type: <class 'str'>` and its default `handle_tool_errors` re-raises, so a
  correctly-blocked call took the whole graph down. The seam now returns the
  type each caller was promised, keyed on `tool_call_id` exactly as langchain's
  own `_format_output` is.
* **Graph input and output are not covered.** There is no library-owned call
  site between the graph and your node functions, so an injected prompt reaches
  the model and a leaked AWS key reaches the caller verbatim. The manifest says
  so. Close it by wiring the middleware's own hooks in as nodes — they are
  ordinary callables, and `AgentMiddleware.wrap_tool_call` is signature-identical
  to LangGraph's `ToolCallWrapper` if you would rather own the tool gate too:

  ```python
  mw = delphi_middleware(agent_id="my-graph", enforcement_mode="block")
  graph.add_node("guard_in",  lambda s: mw.before_model(s, None) or {})
  graph.add_node("guard_out", lambda s: mw.after_model(s, None) or {})
  graph.add_node("tools", ToolNode(tools, wrap_tool_call=mw.wrap_tool_call))
  ```

**Deep Agents: call `protect()` BEFORE `import deepagents`.** Import order is
usually a performance detail. Here it silently decides whether a boundary exists
at all, so it gets its own paragraph. `deepagents` has no seam of its own —
`deepagents.graph` and `deepagents.middleware.subagents` each run
`from langchain.agents import create_agent` at import time, which is a name
rebind — so:

```python
import xaidr
xaidr.protect(agent_id="a", enforcement_mode="block")   # FIRST
from deepagents import create_deep_agent                # then this
```

In that order all three boundaries land, including deepagents' own built-in
tools (`task`, `write_file`) and inside every subagent. Import `deepagents`
first and those modules keep the original builder: the middleware is never
injected, and the model **input and output of every deep agent and subagent go
unscanned** — measured against deepagents 0.7.13, an injected prompt reaches the
model and a leaked AWS key reaches the caller verbatim. Nothing at the call site
looks different, which is why the manifest reports the wrong order as a loud
`found_unpatchable` gap rather than a footnote.

Passing `create_deep_agent(middleware=[delphi_middleware(...)])` by hand is the
other supported wiring, at a known cost: it covers the **parent agent only**.
Subagents are built by a separate `create_agent` call inside
`SubAgentMiddleware` that never sees your list, so a subagent's model output is
unscanned and comes back to the parent as a `ToolMessage` — which no boundary
scans either. Tool *results* are outside every wiring; only tool *arguments* are
scanned. Pinned in `tests/test_real_frameworks.py::TestRealDeepAgents`, import
order included (in child processes, since it is a process-global fact).

**CrewAI is a hook, and the coverage claim is narrower than it was.** Through
1.6.1 this table said `crewai` → `tools.BaseTool.run` → "tool", and the manifest
said "every CrewAI tool invocation is `scan_tool_call`'d before it executes".
**That claim was false and the published 1.6.1 wheel still carries it.**
`BaseTool.to_structured_tool()` binds `CrewStructuredTool(func=self._run)`, so an
agent's tool call runs `invoke()` → `func` → `_run` and never touches
`BaseTool.run`. Measured against crewai 1.15.17: the patch fired on **0 of 3**
agent-driven paths (`Crew.kickoff`, `Crew.kickoff_async`, `Agent.kickoff`) while
a destructive command executed, and the manifest reported the boundary covered
throughout. It shipped because every `protect()` test ran against a hand-written
fake whose `BaseTool.run` *was* the implementation — a CrewAI that never existed.

What replaces it is CrewAI's own `before_tool_call` registry, which fires on all
three of those paths and has a documented block contract. What that does **not**
cover, said plainly rather than left to be discovered:

* a direct `tool.run()` from your own code with no agent — not an agent
  boundary; `sensor.protect_tools(...)` covers it, including CrewAI's tool shape;
* **output**, which `protect()` cannot reach at all. CrewAI's output seam is
  `Task(guardrail=...)`, which is per-`Task` with no registry, so you attach it
  yourself and a `Task` you forget is a `Task` that is not scanned:

  ```python
  from xaidr.integrations.crewai import delphi_guardrail
  Task(description=..., expected_output=..., guardrail=delphi_guardrail(sensor))
  ```

  Note CrewAI **raises** once `guardrail_max_retries` is exhausted, rather than
  returning a refusal the agent can recover from — a harder stop than every
  other boundary here. Catch it at your `kickoff()` call site if that is not
  what you want.

Both facts are now pinned by `tests/test_real_frameworks.py`, which imports the
real framework and skips when it is absent.

**One remaining gap, found by asking the same question of every other seam.** The
CrewAI bug turned on "is this method on the path the framework itself takes",
not "does this method exist", so each remaining fake was re-checked against the
real library at a named version:

| Framework | What is uninstrumented | Mechanism |
|---|---|---|
| `llama-index` | `CodeActAgent` | it collects `tool.real_fn` and calls the underlying function directly, bypassing **both** `FunctionTool.call` and `FunctionTool.acall`. The workflow agents call `tool.acall(**input)` and are covered. Verified against `llama-index-core==0.14.24`. |

Wrap the underlying functions with `sensor.protect_tools([...])` for that one.

**`autogen` (0.2) async tool calls used to be listed here and are now covered.**
The entry described the mechanism correctly — the async reply path is
`a_generate_tool_calls_reply` → `_a_execute_tool_call` → **`a_execute_function`**,
a separate method that never goes through the patched `execute_function` — and
then drew the wrong conclusion, filing a patchable method as unpatchable.
`a_execute_function(self, func_call)` is an ordinary async method on the same
class, taking the same `func_call` dict and returning the same
`(is_exec_success, response_dict)` tuple, and it is now patched with the same
factory and the same refusal shape. Measured against `pyautogen==0.2.35`: a
blocked credential read executed once before, zero times after. A documented gap
is still a gap, and documenting it is not the same as being unable to close it.

**Enforcement shape.** Tool boundaries return a `[BLOCKED]` / `[APPROVAL
REQUIRED]` refusal the agent can read and recover from, rather than raising.
It is a plain string everywhere except one case: the `langchain-core`
`BaseTool.run`/`.arun` seam returns that same text as a **`ToolMessage`** (with
`status="error"`) when the caller passed a `tool_call_id`, because that caller
is a `ToolNode` or a `create_agent` tool loop and a string is not a legal return
there. Direct `tool.run(args)` callers still get the string, and no other
framework's seam is affected. **If you match on the refusal, match on
`str(result)`, not on `isinstance(result, str)`** — see the LangGraph section
above for why this changed in 1.9.0. Transport and entrypoint boundaries raise
`DelphiBlockedError` instead — there is no in-band way for an HTTP send to say
"refused".

`protect()` wires **boundaries only**. Telemetry, policy loading, and the circuit
breaker stay where they already are — the `Sensor` constructor — and everything
you pass beyond `agent_id` / `enforcement_mode` is forwarded to it verbatim
(`reporter=`, `policy_file=`, `circuit_breaker=`, `blocked_urls=`, …). The
breaker in particular stays opt-in: it changes availability, and a one-line
"protect me" call must never quietly add a new way for your app to stop serving.

The three wrappers below are still the right tool when you want a specific
boundary, or a boundary `protect()` reports it cannot reach.

### Protect your tools

`protect_tools` wraps callables (or LangChain `@tool` objects) so every
invocation is scanned and enforced **before** the real tool runs:

```python
sensor = Sensor(agent_id="ops-agent", enforcement_mode="block")
sensor.block_tools(["drop_database"])          # operator blocklist

protected_tools = sensor.protect_tools([run_command, query_db, send_email])
agent = create_agent(model=llm, tools=protected_tools)
```

Each wrapped call runs `scan_tool_call(name, actual_arguments)` before the real
tool executes. A blocked verdict short-circuits: the original tool is **not**
invoked. Explicitly blocked tool names are denied in both monitor and block mode
— an operator's deny is not a detection verdict, so monitor does not downgrade it.
That no-downgrade behavior is enforced by the `protect_tools` wrapper itself:
calling `sensor.scan_tool_call(...)` directly in monitor mode reports `flagged`
rather than `blocked` — deliberate, since telemetry still carries the true verdict.

### Protect outbound HTTP

```python
import httpx

sensor.block_urls(["evil.com", "pastebin.com"])
client = sensor.protect_http(httpx.Client())     # needs xaidr[http]

client.post("http://billing:3002/ask", json={"message": task})
```

Two independent, stricter-wins layers:

- **Destination** — checked on **every** method including GET and DELETE, against
  the blocked-URL list and the YAML deny-destination policy. A denied
  destination is blocked regardless of body content, and regardless of
  enforcement mode: destination blocks are enforced in every mode, monitor
  included (see [Deployment modes](https://github.com/delphisecurity/xaidr/blob/main/README.md#deployment-modes-and-tuning)).
- **Body content** — on POST/PUT/PATCH only. The request body is scanned before
  send, and the response body is scanned before it is returned to the agent. A
  malicious body is blocked even to an allowed destination.

**GET and DELETE are destination-checked, but their response bodies are not
content-scanned.** The destination layer above still applies to them, so a GET to
a denied host is blocked before it leaves. What does not happen is a content scan
of what comes back. That matters, because a GET response is the canonical
indirect-injection vector: your agent fetches a webpage or a document, and the
poisoned instructions arrive in the response body. Scan fetched content yourself,
at your input boundary, before it reaches the model:

```python
page = client.get("https://example.com/doc")     # destination-checked only
r = sensor.scan(page.text, direction="input")    # you scan the content
if r.action in ("blocked", "approval_required"):
    return "Fetched content rejected."
```

**Supported verbs:** `get`, `post`, `put`, `patch`, `delete` (plus `close` and
use as a context manager). Other verbs are **not** proxied: `head`, `options`,
`request`, `stream`, and `send` raise `AttributeError` rather than falling
through to the wrapped client. If you need one of those, call it on your own
`httpx.Client` and scan at your input boundary as above.

### LangChain middleware

One middleware object covering all three agent boundaries with a single sensor:

```python
from langchain.agents import create_agent
from xaidr.integrations.langchain import delphi_middleware

agent = create_agent(
    model="anthropic:claude-sonnet-4-5",
    tools=[search_tool, send_email],
    middleware=[delphi_middleware(agent_id="support-agent",
                                  enforcement_mode="block")],
)
```

| Boundary | Hook | Scans via | On block |
|---|---|---|---|
| Input | `before_model` | `scan` / `scan_a2a` (auto-routed by message shape) | refusal `AIMessage`, jump to end |
| Tool call | `wrap_tool_call` | `scan_tool_call` — name + args, **before execution** | refusal `ToolMessage`, tool **not** invoked |
| Output | `after_model` | `scan_output` | refusal `AIMessage`, jump to end |

Inbound messages are shape-routed: a serialized JSON-RPC A2A envelope goes to
`scan_a2a`, anything else goes
to `scan`. All three hooks fail open. `reporter=` and any `Sensor` keyword pass
through.

**MCP note:** MCP tool calls that flow through LangChain's tool interface are
covered by `wrap_tool_call`. MCP-specific surfaces outside that path should be
covered by scanning what enters through your normal tool boundary.

### Haystack Agent hooks

> **Read this before you read your logs.** A blocked input makes Haystack log
> **`Agent reached maximum agent steps of N, stopping.`** at WARNING. **That is
> not a step-budget exhaustion — it is a security block**, and the two are
> indistinguishable in the log. Stopping the run is only possible from a
> `before_run` hook by exhausting the step budget (a hook cannot `break` the
> Agent's loop), the line is emitted by `haystack.components.agents`, and
> **nothing in a hook can suppress it**.
>
> What you can trust instead is the Agent's **return value**, which this
> integration repairs: `exit_reason` reads **`"xaidr_blocked"`** and
> `step_count` reads `0`, rather than `"max_agent_steps"` and `2**62`.
> **`"xaidr_blocked"` is NOT one of Haystack's documented `exit_reason` values**
> (`"text"`, a tool name, `"max_agent_steps"`), so **any `ConditionalRouter` or
> branch reading `exit_reason` needs a case for it** or it will fall through to
> your default path. Import it rather than typing it:
> `from xaidr.integrations.haystack import EXIT_REASON_BLOCKED`. A block that
> rendered as `"text"` would be a block nothing downstream could route on, which
> is why it is not one.

Haystack's hooks are a **constructor argument**, not a middleware list and not a
global registry, so `delphi_hooks()` returns the `hooks=` mapping itself:

```python
from haystack.components.agents import Agent
from xaidr.integrations.haystack import delphi_hooks

agent = Agent(
    chat_generator=OpenAIChatGenerator(),
    tools=[search_tool, send_email],
    hooks=delphi_hooks(agent_id="support-agent", enforcement_mode="block"),
)
```

| Boundary | Hook point | Scans via | On block |
|---|---|---|---|
| Input | `before_run` | `scan` | refusal assistant message; **the chat generator is never called** |
| Tool call | `before_tool` | `scan_tool_call` — name + args, **before execution** | the call is removed and a refusal tool-result takes its place; the tool is **not** invoked |
| Output | `after_run` | `scan_output` | the final assistant message is replaced |

Merge it with hooks of your own rather than replacing either —
`hooks.setdefault("before_llm", []).append(my_hook)`. All three fail open, and
`reporter=` and any `Sensor` keyword pass through. `Agent.run_async` is covered
by the same hooks; it is a separate loop in Haystack and is tested separately here.

**A hook cannot return a verdict, so each boundary blocks by rewriting `State`.**
Haystack's `Hook` protocol is `run(state) -> None` — there is no `return False`
as in CrewAI and no `jump_to` as in LangChain. Each rewrite uses the mechanism
the Agent documents at that point, and the tool refusal is shaped exactly like
Haystack's own `ConfirmationHook` shapes a rejection (an assistant message
carrying the rejected call, then a `ChatMessage.from_tool(..., error=True)`), so
the Agent loops on and can recover rather than dying on the rewrite. One blocked
call in a parallel batch does not cancel its siblings.

Branching on the repaired `exit_reason` (see the callout at the top of this
section) looks like this:

```python
from haystack.components.routers import ConditionalRouter
from xaidr.integrations.haystack import EXIT_REASON_BLOCKED

router = ConditionalRouter(routes=[
    {"condition": "{{ exit_reason == '" + EXIT_REASON_BLOCKED + "' }}",
     "output": "{{ last_message }}", "output_name": "refused",
     "output_type": ChatMessage},
    {"condition": "{{ True }}",
     "output": "{{ last_message }}", "output_name": "answer",
     "output_type": ChatMessage},
])
```

**Two things this does not cover, said here rather than left to be discovered.**

* **Tool RESULTS are not scanned** — only tool ARGUMENTS are. Haystack *does*
  offer the seam (`after_tool` runs once the result messages are in `State`);
  this build deliberately does not register there, so a tool that returns an
  injected payload reaches the model verbatim. It is reported as
  `found_unpatchable` and pinned by a negative test. Close it yourself with an
  `after_tool` hook calling `sensor.scan(result, direction="input")`.
* **A `Pipeline` with no `Agent` in it gets nothing.** These are the *Agent's*
  hooks. `Pipeline._run_component` calls `instance.run(**inputs)` on an
  arbitrary per-component dict with no notion of a user message, so there is no
  honest message-shaped scan to make there and none is attempted. Call
  `sensor.scan()` / `scan_output()` at your own entry and exit points for a RAG
  pipeline. Also pinned by a negative test.

**Why the seam is `Agent.__init__` and not `Tool.invoke`,** which is the more
robust *kind* of seam (a method seam reaches objects that already exist).
Measured against haystack-ai 3.1.1: the Agent calls `tool.invoke(**args)` where
`args` is `_prepare_tool_args(...)` output — the model's arguments *after*
`_inject_state_args` has merged in `State` values and possibly a streaming
callback — so scanning there means scanning a live `State` object alongside the
model's text, and `Tool.invoke`'s only refusal channel is a return value, which
records the call as having run. `before_tool` sees `tool_call.arguments`, which
is exactly `scan_tool_call`'s input with nothing added and nothing lost, and
removes the call before the executor sees it. The price of that choice is the
constructor seam's one real limit, which is a test rather than a footnote: an
`Agent` **constructed before `protect()`** keeps the hooks it was built with and
is not instrumented. There is no import-order trap of the `deepagents` kind —
`Agent.__init__` is a class attribute — so calling `protect()` again after
importing your agent modules covers every `Agent` built from then on.

**Serialization.** `Agent.to_dict()` and `Pipeline.dumps()` work with these
hooks attached; what round-trips is `agent_id` and `enforcement_mode`, not a
live `Sensor`, so a `reporter=` / `policy_file=` / circuit breaker must be
rebuilt in the loading process. Loading also needs an explicit opt-in, because
Haystack refuses to deserialize a class whose module is not on its trusted list:

```python
from haystack.core.serialization import allow_deserialization_module
allow_deserialization_module("xaidr.integrations.haystack")
```

Everything above is pinned by
`tests/test_real_frameworks.py::TestRealHaystack`, which imports the real
`haystack-ai` and skips when it is absent.

---

