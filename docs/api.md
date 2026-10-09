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
request. If you do construct them per request, the telemetry worker now stops
when the sensor is collected (1.3.0); `close_sync()` remains the explicit way to
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
- **How to open a flow:** `with xaidr.flow(principal=...):` around each agent request, outside any LangGraph graph. It opens one request's scope (chain, correlation id and a fresh value-origin ledger) and ends it on exit, whether the request returned or raised. A sync request handler can be decorated with `@xaidr.flow(...)`, which scopes each call; `async def`, generator and async-generator functions are refused, because their bodies run after the call returns, so use the `with` form inside them. A decorated handler reads the id with `xaidr.provenance_chain.current_correlation_id()`.
- **The plain pair, and its limitation:** `begin_flow()` ... `clear_flow()` still works. But if `clear_flow()` is skipped, for example because the request raised, the next request on the same worker thread inherits the flow and its ledger. If you use the pair, call `clear_flow()` in a `finally`.
