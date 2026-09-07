# Provenance and audit trail

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

## Provenance and audit trail

Records *who an action is on behalf of* and traces the delegation chain across
agents — the visibility a gateway or IdP cannot get, because it lives inside the
agent mesh.

```python
from xaidr import set_origin, origin_scope

# at your request entry point, AFTER your app authenticated the user:
set_origin(on_behalf_of="user:alice", correlation_id="req-123")
# every scan in this flow now carries that principal in telemetry + provenance

with origin_scope(on_behalf_of="user:alice"):
    sensor.scan(user_input, direction="input")
```

Multi-hop, across process boundaries, over W3C Trace Context:

```python
from xaidr import inject_context, extract_context

# agent A, before calling B — RETURNS a new headers dict; it does not mutate
headers = inject_context({"content-type": "application/json"})
# -> adds: traceparent, x-openA2A-correlation, x-openA2A-chain
httpx.post("http://agent-b/ask", json=payload, headers=headers)

# agent B, on receive — returns True if context was found and restored
extract_context(request.headers)
```

Two carriers, mirroring distributed tracing. **In-process**, `contextvars` carry
the chain across async tasks and threads with no app effort. **Cross-boundary**,
the chain rides the standard `traceparent` header plus a companion entry for the
correlation id and a compact chain header — the same mechanism OpenTelemetry
uses, reused rather than reinvented. Telemetry records the chain, its depth, and
a correlation id stable across the boundary.

**What crosses the boundary, and what does not.** The delegation chain, its
depth, and the correlation id cross via those headers. The `on_behalf_of`
principal set by `set_origin()` does **not**: it is contextvar-local to the
process that set it. `inject_context()` does not serialize it, so the receiving
process gets the chain and the correlation id but no principal, and its telemetry
carries no `on_behalf_of` unless you re-establish one:

```python
# agent B, on receive
extract_context(request.headers)                 # chain + correlation id restored
set_origin(on_behalf_of="user:alice")            # principal: re-establish it yourself
```

One exception worth knowing, because it changes what you have to do: a principal
seeded with `begin_flow(principal="user:alice")` becomes the **head of the
chain**, and the chain is what crosses. In that shape the principal does reach
the next hop and the receiver's provenance carries it with no extra call. It is
`set_origin()` on its own that stops at the process edge. If you use
`set_origin()` alone, note that the `correlation_id` you pass it is likewise not
the one `inject_context()` emits; a fresh id is minted for the outbound flow.

**The honest caveat, stated plainly:** `xaidr` does **not** authenticate and does
not connect to an identity provider. `set_origin` takes an **app-supplied
string** and records it — it does not verify a token. Your application must
prove identity at its own auth boundary (validate the Entra / Ping / OAuth
token) and pass the *result* in. The value here is **propagation and audit**, not
authentication. Likewise, an un-instrumented hop does not append itself, so the
chain shows an honest gap rather than a guessed one, and a purely LLM-mediated
handoff (A's prose becomes B's prompt, no call, no headers) carries no metadata
and cannot be continued. Missing provenance is emitted as missing — never
fabricated.

---

