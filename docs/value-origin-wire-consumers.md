# The value-origin wire vocabulary and its consumer

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

The sensor reports where a tool call's destination came from as `valueOrigin`, at
the top level of `data` on every tool-call event (every exit of `scan_tool_call`,
never null), mapped to `gen_ai.security.value_origin`, at schema **0.3.0**. The
vocabulary has **fifteen** values (`xaidr.value_origin.WireValue`). Row state and
row text are `row_text()`'s; `tests/value_origin_conformance/row_text.json` is the
machine-readable copy.

## The consumer

The consumer of the wire field is **Delphi Core** (`delphisecurity/delphi`). Core
must accept all fifteen values before anything depends on the `"v2"` set: before
a sensor is configured with `value_origin_wire="v2"`, and before any view, query
or policy reads one of the six values `"v1"` withholds.

## The fifteen values

| wire value | verdict | row state | in `v1` | blocks under ENFORCE | row text (tool call) |
|---|---|---|---|---|---|
| `principal` | authorized | ran_clean | yes | no | Intent: destination traces to the principal's own input (a declared principal span). |
| `principal_undeclared_span` | authorized | ran_clean | yes | no | Intent: destination traces to the principal's input — assuming the whole input was the principal's own; no span structure was declared, so quoted content would read the same. |
| `trusted_source` | authorized | ran_clean | yes | no | Intent: destination traces to a designated trusted source. |
| `untrusted_source` | unauthorized | ran_evidence | yes | yes: `ORIGIN_UNTRUSTED_DESTINATION` | Intent: destination traces to an untrusted source. |
| `unresolved` | unresolved | ran_evidence | yes | no | Intent: destination origin unresolved — it traces to no recorded source. |
| `no_destination` | not_evaluated | not_applicable | yes | no | Intent: not applicable — this call carries no destination-shaped value. |
| `no_flow` | not_evaluated | not_recorded | yes | no | Intent: not evaluated — no flow context was visible to this call (none was started, or it did not reach this thread). |
| `ledger_absent` | not_evaluated | not_recorded | yes | no | Intent: not evaluated — a flow was active but its provenance ledger was never bound; the sensor's flow entry is not wired. |
| `ledger_saturated` | not_evaluated | not_recorded | yes | no | Intent: not evaluated — this flow's ledger was full; an unmatched destination cannot be called novel. |
| `input_truncated` | not_evaluated | not_recorded | no | no | Intent: not evaluated — this destination traces to no recorded source; the principal's input was longer than value origin examines whole (64 KiB), and the part past that point was scanned only for destination addresses. |
| `argument_bound` | unresolved | ran_evidence | no | no | Intent: destination not fully examined — this call's arguments exceed what value origin examines whole (a value over 4,000 characters, more than 64 values, or nesting deeper than 6); past that point they were scanned only for destination addresses. |
| `result_truncated` | not_evaluated | not_recorded | no | no | Intent: not evaluated — this destination traces to no recorded source; a tool result in this flow exceeded what value origin examines whole (a value over 65,536 characters, more than 64 values, or nesting deeper than 6), and the part past that point was scanned only for destination addresses. |
| `result_unread` | not_evaluated | not_recorded | no | yes: `ORIGIN_UNEXAMINABLE_SOURCE` | Intent: not evaluated — a tool result in this flow was an unread network response (httpx, requests, urllib3 or aiohttp), which value origin does not read so as not to consume it; a destination in it cannot be traced. |
| `extraction_incomplete` | not_evaluated | not_recorded | no | no | Intent: not evaluated — value origin's scan for destination addresses in a long value reached its work budget; the rest was not scanned, so a destination there may be missed. |
| `write_dropped` | not_evaluated | not_recorded | no | yes: `ORIGIN_UNEXAMINABLE_SOURCE` | Intent: not evaluated — a write to this flow's ledger was lost (the ledger was full, or recording it faulted), so value origin does not know what that input or result named; a destination it does not know is treated as unexaminable. |

`untrusted_source` also adds the `intent.value_origin_untrusted` category, and so
do `result_unread` and `write_dropped`. A value that does not block never changes
an action.

## What the sensor emits: `Sensor(value_origin_wire=...)`

- `"v1"`, the default: the nine values marked in `v1` above.
- `"v2"`: all fifteen.
- `"off"`: none.

A value outside the active set is withheld from every reporter (SIEM and file
reporters included): the `valueOrigin` key is absent, which on the wire reads the
same as a sensor that does not report it. Each withheld value is named in a
warning once per sensor, and every value stays on `ScanResult.value_origin`.
`tests/test_value_origin_m9.py` pins `"v2"` to every `WireValue`.

## A direct scan carries no value

A host that calls `sensor.scan(text, direction="tool_call")` directly, instead of
`scan_tool_call`, emits a tool-call event without `valueOrigin`: value origin
evaluates tool calls in `scan_tool_call`. No caller inside xaidr does this.
