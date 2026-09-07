# API reference

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

```python
from xaidr import (
    Sensor, ProtectedHttpClient, ScanResult, DelphiBlockedError, CircuitBreaker,
    set_origin, origin_scope, clear_origin,
    begin_flow, inject_context, extract_context, clear_flow, propagate_context,
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

Direct scan APIs return `ScanResult`; check `.action` (one of the
[four values](#the-four-action-values)), or the `.is_blocked` /
`.is_allowed` / `.requires_approval` / `.must_halt` properties. `.must_halt` is
the one to gate execution on — it covers `blocked` and `approval_required`
without also stopping on `flagged`. The protected HTTP wrapper raises
`DelphiBlockedError` when it blocks a request before network execution.

---
