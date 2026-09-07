# Circuit breaker

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

## Circuit breaker

**Opt-in, and off by default.** Without `circuit_breaker=`, a sensor behaves
exactly as it does today — no counters, no state, no extra telemetry.

Everything else in `xaidr` fails **open**: an internal fault returns `allowed`,
and the sensor never takes your agent down. The circuit breaker deliberately does
the opposite — when it trips it **halts the agent**. That inversion is the whole
reason it is opt-in: you are trading availability for containment, and that is
your call to make, not a default we pick for you.

```python
from xaidr import Sensor, CircuitBreaker

sensor = Sensor(
    agent_id="support-agent",
    enforcement_mode="block",
    circuit_breaker=CircuitBreaker(
        violation_threshold=3,       # 3 blocked verdicts...
        violation_window_sec=60,     # ...within 60s → open the circuit
        rate_threshold=50,           # 50 tool calls...
        rate_window_sec=60,          # ...within 60s → open the circuit
        delegation_rate_threshold=20,      # 20 OUTBOUND scan_a2a delegations...
        delegation_rate_window_sec=60,     # ...within 60s → open the circuit
        cooldown_sec=300,            # auto-close after 5 min
        on_trip=lambda trip: page_oncall(trip["reason"]),
    ),
)

sensor.circuit_state     # "closed" | "open"
sensor.reset_circuit()   # close now, clear all three counters
```

### What it counts

Three counters. That is the entire mechanism — it does **not** model erratic,
anomalous, or novel behavior, and it will not notice an attack that does not show
up in one of these three numbers.

| Trigger | Counts | Does not count |
|---|---|---|
| `violation_threshold` | verdicts whose **true** action is `blocked` | `flagged` below your `block_threshold`; `approval_required` |
| `rate_threshold` | `scan_tool_call` invocations | `scan()` / `scan_output()` — a chatty agent must not trip it |
| `delegation_rate_threshold` | **outbound** `scan_a2a` invocations | `scan_a2a(received=True)`; tool calls |

Any trigger alone opens the circuit. A trigger left at `None` is disabled, so you
can run one, two, or all three. The trip reason (`"violation_threshold"`,
`"rate_threshold"` or `"delegation_rate_threshold"`) is recorded, handed to
`on_trip`, and mapped to `gen_ai.security.circuit_breaker.reason`. Every trip
reports all three counts, whatever tripped it, because the useful question at
trip time is what *else* was happening.

**Delegation is its own counter, not part of the tool-call rate.** An agent
calling forty tools in a minute is doing its job; an agent delegating to forty
peers in a minute is a fan-out storm, and it is the second one that cascades,
because each peer is itself an agent that will call tools and delegate again.
One combined counter would force a single threshold to be either too low for the
chatty tool user or too high to catch the storm, and `reason="rate_threshold"`
would not tell you which had happened.

**Only outbound delegations count.** `scan_a2a(received=True)` is work arriving
*from* another agent, which the receiving sensor did not choose to accept.
Counting inbound would open the circuit of a popular shared agent — a billing
agent fifty peers delegate to — for being popular, and a breaker that halts a
healthy service under load has manufactured the cascading failure it exists to
contain. Ingress flood control belongs at the transport.

**`delegation_rate_threshold` defaults to `None`, like its two siblings.** It is
off unless you set it. Turning it on by default would hand every existing
`CircuitBreaker(violation_threshold=…)` deployment a second way to stop serving,
on upgrade, without editing anything — and there is no honest default value,
since a supervisor fanning out to twenty workers is routine in one deployment and
an incident in another.

> **Fixed in this release, and it was live.** Through 1.10.0 the sensor called a
> `record_delegation` method the breaker runtime did not implement. Every
> outbound `scan_a2a` with a breaker configured raised `AttributeError`, the
> fail-open handler caught it, and the count was dropped — so the delegation
> trigger did not exist while appearing to, and `circuit_state` kept reporting
> `"closed"`. Measured on the published 1.10.0 wheel: 50 delegations against a
> threshold of 5 left the circuit closed. A counter that faults now reports
> **once** at ERROR and says the trigger is not counting, and
> `tests/test_delegation_rate_breaker.py` asserts that every method the sensor
> calls on the runtime is implemented, so the class of bug cannot recur silently.

**"True" action is load-bearing.** The violation counter sees the verdict *before*
monitor mode downgrades `blocked` to `flagged`. A breaker that counted the
returned action could never trip in monitor mode, which would make it useless
during exactly the phase where you are trying to learn what your traffic does.

### While the circuit is open

- **`block` mode:** every subsequent scan returns `action="blocked"` with category
  `circuit_breaker_open` and rule `CIRCUIT_BREAKER_OPEN`, **without running
  detection**. A wrapped tool is not invoked. The distinct rule is there so a
  breaker halt is never mistaken for a content block during triage.
- **`monitor` mode:** the breaker still trips, still emits telemetry, and still
  fires `on_trip` — but **nothing is blocked**. Monitor's contract holds. This is
  how you calibrate thresholds against real traffic before enforcing.
- `on_trip` fires **exactly once per trip**, not once per subsequent scan.
- A trip and a close each emit one telemetry event of type `circuit_breaker`
  (*not* `"scan"`), carrying the trigger reason and the counter values.

### Recovery

| | |
|---|---|
| `cooldown_sec=300` | auto-closes 5 minutes after the trip; all three counters cleared |
| `cooldown_sec=None` | stays open until you call `reset_circuit()` — the manual kill-switch form |
| `reset_circuit()` | closes immediately and clears all three counters, any time |

There is no half-open state: the circuit is closed or open. Recovery is a
cooldown or an operator, nothing probabilistic.

```python
# Kill-switch form: trip once, stay down until a human clears it.
CircuitBreaker(violation_threshold=5, cooldown_sec=None, on_trip=page_oncall)
```

A fault *inside* the breaker degrades to "no breaker" — the scan still returns its
verdict — so the one component that can halt your agent cannot halt it by
malfunctioning. A raising `on_trip` callback is logged and swallowed for the same
reason.

---

