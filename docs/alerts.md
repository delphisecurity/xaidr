# Where alerts go

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

## Where alerts go

`xaidr` has **no UI**, and that is a design decision, not a gap. Every scan emits
one structured telemetry event to a pluggable **Reporter**; you point it at the
tooling you already operate. This is the Falco / Trivy model.

The scan's *return value* drives your control flow. The *reporter* is your
observability. Two separate things.

**One thing to encode in your SIEM rules:** because destination blocks are
enforced in every mode, a destination block emits an event carrying
`action="blocked"` together with the sensor's actual `enforcementMode`, which may
be `"monitor"`. A rule that assumes monitor mode never produces a blocked action
needs to account for that combination. It is truthful, not a bug — the request
genuinely was blocked and never reached the network.

**A second thing, if you already run rules keyed on `category`:** shell command
inspection reports under a category of its own, `credential_access`, rather than
borrowing a neighbouring one. It appears in `.category` on the returned
`ScanResult`, in the `category` field of the emitted event, and as
`gen_ai.security.detection.category` in the `openA2A` schema. A rule that
enumerates categories explicitly will not match it until you add it.

**A third thing, and it will change your event volume:** tool calls now emit
`jailbreak`, `system_prompt_leak`, `encoding_evasion`, `dos_attempt` and
`forged_trust` with `direction="tool_call"`. Those five families were dropped
from the tool path in earlier versions and are now reported at **flag** level —
so the same traffic produces more `flagged` events than before, and none of them
are new blocks. Dashboards that chart flagged-event counts over time will show a
step. The reasoning for flag rather than block, and the `category:` policy rule
that escalates a family to a block in your deployment, are under
[Policies](https://github.com/delphisecurity/xaidr/blob/main/docs/policies.md).

**Alerting on the impact class.** The class a call was assigned is carried
separately from the detection category, as `impactClass` in the native event and
`gen_ai.security.authz.impact_class` in the mapped schema, beside the tier. That
is where `escalate`, `persist`, `evade`, `infra_destruction` and
`destructive_filesystem` surface.

This is the attribute to key on for the [classify-only
decisions](https://github.com/delphisecurity/xaidr/blob/main/docs/policies.md), and it is worth saying why: those calls never block, so
the event is their *only* output. A `terraform destroy` is `allowed` with no
detection category at all, and the impact class is the single field that tells
your SIEM it was infrastructure teardown rather than an ordinary tool call:

```json
{"gen_ai.security.detection.action": "allowed",
 "gen_ai.security.detection.score": 0.0,
 "gen_ai.security.authz.impact_class": "infra_destruction",
 "gen_ai.security.authz.impact_tier": "critical",
 "gen_ai.tool.name": "run_command"}
```

Omit-don't-guess applies here as everywhere else: a call that matched no class
carries no attribute rather than the literal `"unknown"`, so absence means
unknown and you never have to distinguish a real class from a placeholder.

```python
from xaidr.reporters import (
    StdoutReporter, FileReporter, WebhookReporter, OTelReporter, MultiReporter,
)

Sensor(agent_id="a")                                              # stdout (default)
Sensor(agent_id="a", reporter=FileReporter("events.jsonl"))       # JSONL → SIEM agent
Sensor(agent_id="a", reporter=WebhookReporter(url=SIEM_INGEST_URL))
Sensor(agent_id="a", reporter=OTelReporter())                      # → OTel pipeline
Sensor(agent_id="a", reporter=MultiReporter(
    FileReporter("events.jsonl"),
    WebhookReporter(url=SLACK_WEBHOOK_URL),
))
```

`MultiReporter` isolates each sink — one failing reporter does not stop the
others. Any object with `report(list[dict])` and `close()` is a valid reporter,
so a custom sink is one class and one line, with no change to the sensor:

```python
class SlackAlerts:
    """Forward only real threats — no channel spam."""
    def __init__(self, url):
        self.url = url
    def report(self, batch):
        for e in batch:
            d = e.get("data", {})
            if d.get("action") in ("flagged", "blocked"):
                post_to_slack(self.url, f"[{d['action']}] {d.get('category')} "
                                        f"score={d.get('score')} agent={d.get('agentId')}")
    def close(self):
        pass

sensor = Sensor(agent_id="support-agent", reporter=SlackAlerts(SLACK_URL))
```

**Content is never emitted raw.** The prompt is carried as a stable truncated
SHA-256 plus its length, so SIEM telemetry can correlate repeated content without
shipping the content itself. In the `openA2A` schema, each event also carries a
human-readable `message`, a stable `severity`, and — when an internal fault made
the sensor fail open — a `degraded` flag and the fault's `error_type`, so a
reduced-assurance verdict is never mistaken for a clean `allowed`.

**Flushing matters.** Telemetry is batched and delivered from a background
thread (`telemetry_batch_size`, `telemetry_flush_interval_sec`) so it never
blocks the request path. Before reading the sink:

- **Sync code:** `sensor.flush()` (keeps emitting afterwards) or
  `sensor.close_sync()` (full shutdown). Both are idempotent.
- **Async code:** `await sensor.close()`.

`close()` is a *coroutine* — in sync code, calling it without `await` is a silent
no-op. Use `close_sync()`.

### Vendor-neutral schema for SIEM

```python
sensor = Sensor(agent_id="a", schema="openA2A",
                reporter=FileReporter("events.jsonl"))
```

Events map to the OpenTelemetry-aligned `gen_ai.security.*` namespace — flat,
dotted attributes that drop straight onto a span or log record, reusing existing
OTel attributes (`gen_ai.agent.id`, `gen_ai.tool.name`) rather than re-minting
them:

```
gen_ai.security.schema_version        gen_ai.security.detection.action
gen_ai.security.event_type            gen_ai.security.detection.score
gen_ai.security.event_id              gen_ai.security.detection.category
gen_ai.security.timestamp             gen_ai.security.detection.rules
gen_ai.agent.id                       gen_ai.security.detection.enforcement_mode
gen_ai.security.interaction.type      gen_ai.security.detection.latency_ms
gen_ai.security.interaction.direction
gen_ai.security.interaction.content_hash
gen_ai.security.authz.impact_class    gen_ai.security.authz.decision
gen_ai.security.authz.impact_tier     gen_ai.security.authz.policy_id
trace_id  span_id  trace_flags        gen_ai.security.trace.source
```

**Two event types, and the record says which.**
`gen_ai.security.event_type` is `scan` or `circuit_breaker`. A breaker
transition is a state change of the sensor, not a verdict on a message, so it
carries `gen_ai.security.circuit_breaker.*` (`transition`, `reason`,
`close_method`, `violations`, `tool_calls`, and whichever thresholds are
enabled) and **no** `detection.*` or `interaction.*` attributes. Do not write a
query that assumes every mapped record has a verdict. A disabled trigger is
omitted rather than emitted as null, because absent already means unknown here
and null is what a chart reads as zero.

**Timestamps are stamped at scan time, in UTC with microseconds**
(`2026-08-31T22:41:26.766832Z`). Before schema 0.2.0 the mapper minted this
itself, which meant it recorded when the telemetry batch drained rather than
when anything happened: mapping runs in the flush worker, up to
`flush_interval_sec` after the scan, and a batch of up to 50 events all received
near-identical stamps. The native event now carries its own `timestamp` and the
mapper reads it.

**Trace correlation reuses the OpenTelemetry names.** `trace_id`, `span_id` and
`trace_flags` are emitted top-level, not under `gen_ai.security.*`, so a
consumer already joining on them does not have to special-case this producer.
`gen_ai.security.trace.source` (`wire` or `otel`) is ours, because how the
parent context was obtained is an xaidr observation with no standard attribute.

Consumers on **schema 0.1.0** should note that 0.2.0 changes the timestamp's
meaning and its format, and introduces a record type that is not a scan. Branch
on `gen_ai.security.schema_version`; that is what it is for.

The schema propagates to built-in reporters that support `schema=`. A reporter
with its own explicit `schema=` keeps it; the sensor's fills in built-in
reporters that did not choose one. A fully custom reporter receives the internal
event shape unless it calls `xaidr.schema.to_openA2A(event)` itself. Missing
fields are **omitted, never guessed**: a consumer treats an absent provenance
field as "unknown", never as "safe".

With `xaidr[otel]`, `OTelReporter` emits each event as an OTel log record. Note
the two-part activation: the reporter *emits*, but you must configure a
`LoggerProvider`/exporter from the OpenTelemetry SDK (installed separately —
this package deliberately stays API-only) to actually ship records. Without one,
emitting is a safe no-op.

**Splunk.** A Technology Add-on lives in
[`integrations/splunk/TA-xaidr/`](integrations/splunk/TA-xaidr/): two
sourcetypes and the search-time extractions that normalise both the native and
the openA2A shapes onto one `xaidr_*` field namespace, so a search written once
works against either. Configuration only — no scripts, no inputs, no custom
search commands. Verified on a real Splunk 10.4.2 instance; clean on
`splunk-appinspect` for both the cloud tag set and the full set.

---

