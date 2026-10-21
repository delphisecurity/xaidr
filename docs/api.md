# API reference

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

```python
from xaidr import (
    Sensor, ProtectedHttpClient, ScanResult, DelphiBlockedError, CircuitBreaker,
    set_origin, origin_scope, clear_origin,
    flow, begin_flow, inject_context, extract_context, clear_flow, propagate_context,
)

Sensor(agent_id="a", privilege_tier=1)      # 1 = highest privilege, 4 = lowest
from xaidr.reporters import (
    StdoutReporter, FileReporter, WebhookReporter, OTelReporter, MultiReporter,
)
from xaidr.integrations.langchain import delphi_middleware
```

Sensors are designed to be long-lived — construct one per agent, not per
request. If you do construct them per request, the telemetry worker stops
when the sensor is collected; `close_sync()` remains the explicit way to
flush and stop one early.

| Method | Purpose |
|---|---|
| `scan(prompt, direction="input")` | inbound text |
| `scan_output(response)` | model output / leak check |
| `scan_tool_call(name, arguments)` | tool + MCP invocations |
| `scan_a2a(message, destination, received=False)` | A2A envelopes |
| `set_policy(dict)` | programmatic policy |
| `block_tools(names)` / `unblock_tools(names)` | operator tool blocklist |
| `block_urls(urls)` / `unblock_urls(urls)` | operator destination blocklist |
| `protect_tools(tools)` | wrap tools with enforcement (idempotent — a tool already wrapped is returned unchanged) |
| `protect_http(client)` | wrap an `httpx.Client` |
| `privilege_tier` | this sensor's configured [tier](https://github.com/delphisecurity/xaidr/blob/main/docs/privilege-tiers.md) (property; read-only, set at construction) |
| `circuit_state` | `"closed"` / `"open"` (property; always `"closed"` with no breaker) |
| `reset_circuit()` | close the circuit breaker now, clear its counters |
| `flush()` / `close_sync()` | sync telemetry flush / shutdown |
| `await close()` | async shutdown |

**`direction` is the audit label, not a detection switch.** `scan()` accepts
`"input"` (a principal's text), `"tool_result"` (what a tool or MCP server
returned), `"output"` (model output — use `scan_output()`) and `"a2a"` /
`"a2a_inbound"` (A2A envelopes — use `scan_a2a()`). `"input"` and
`"tool_result"` run the **identical** pipeline and give the same bytes the same
verdict; they differ in what the telemetry event, and any extension's
`ScanRequest`, records about where the text came from. Pass `"tool_result"` for
anything a tool handed back: a result that says *"ignore your instructions"* is
the headline MCP attack, and recording it as `"input"` attributes it to the user
who merely asked a question.

Direct scan APIs return `ScanResult`; check `.action` (one of the
[four values](#the-four-action-values)), or the `.is_blocked` /
`.is_allowed` / `.requires_approval` / `.must_halt` properties. `.must_halt` is
the one to gate execution on — it covers `blocked` and `approval_required`
without also stopping on `flagged`. The protected HTTP wrapper raises
`DelphiBlockedError` when it blocks a request before network execution.

---


## The one-time `no_flow` warning (value origin)

- **What it means:** a tool call arrived with no flow active, so value origin could not trace its destination (logged once per sensor).
- **How to open a flow:** `with xaidr.flow(principal=...):` around each agent request, outside any LangGraph graph. It opens one request's scope (chain, correlation id and a fresh value-origin ledger) and ends it on exit, whether the request returned or raised. A sync request handler can be decorated with `@xaidr.flow(...)`, which scopes each call. An `async def`, a generator function, or anything whose call returns a coroutine is refused, because its body would run after the call returns, outside the scope: in an `async def`, write the `with` form inside its body. A scope cannot be opened inside a generator's body (that body runs whenever the generator is resumed or collected); open it around the code that consumes the generator. A sync handler's returned generator (a WSGI body, say) is iterated outside the scope. A scope opened inside an open scope JOINS it: same request, same flow, and its `principal=` is not applied. Opened while a flow is already active with no scope of its own (a `begin_flow()`, an `extract_context()`, a recorded hop), it leaves that flow's chain, tiers, correlation id and inbound mark exactly as they are, so it never loosens the privilege-tier gate, and its `principal=` is not applied; it gets its own value-origin ledger. A decorated handler reads the id with `xaidr.provenance_chain.current_correlation_id()`. `set_origin()` is not part of the flow; use `origin_scope()` for it.
- **Each request's ledger ends with the request.** A value-origin ledger belongs to the request it is bound in and closes when that request ends; a closed ledger reads as not bound everywhere, including in work the request started that outlives it. The requests: each `ThreadPoolExecutor` job, each CrewAI kickoff and Agents SDK run hooked by `protect()`, each fresh `xaidr.flow()`, and each `with xaidr.request_scope():` block. `request_scope()` always starts a new request; a hooked run or `flow()` inside a live `request_scope()`, run or `flow()` joins it, and inside an executor job is its own request. A ledger bound outside the request (a bare `begin_flow()`, the enclosing request's) is hidden inside it and back after it. In a `request_scope()` block or a hooked run, every input keeps authorizing for the rest of it.
- **`xaidr.request_scope()`** marks one request for a server the sensor cannot see begin one, such as a loop that handles request after request on one thread: `with xaidr.request_scope(): handle(request)` (or `async with` inside an `async def`). It never begins a flow and never touches the provenance chain, tiers or the inbound mark.
- **The plain pair:** `begin_flow()` ... `clear_flow()` still works, and the ledger `begin_flow()` binds ends with the request it is begun in. Outside any request, if `clear_flow()` is skipped, for example because the request raised, the next request on the same thread inherits the flow and its ledger. If you use the pair, call `clear_flow()` in a `finally`, or open `xaidr.request_scope()` around each request.
