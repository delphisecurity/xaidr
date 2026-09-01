# TA-xaidr

Technology Add-on for [xaidr](https://github.com/delphisecurity/xaidr) agent-security
telemetry.

Configuration only. This add-on ships **no `bin/` directory, no scripts, no
modular inputs, no custom search commands, and no network calls**. It is two
sourcetypes and the extractions that go with them. Getting the events into
Splunk is your job (a universal forwarder tailing the file, HEC, or whatever
your collection tier already does); this add-on makes them searchable once they
arrive.

Version 1.1.0. Targets **xaidr telemetry schema 0.2.0**. Verified on a real
**Splunk 10.4.2** instance — see [How this was verified](#how-this-was-verified).

Reading data from an older xaidr? See [Pre-0.2.0 data](#pre-020-data).

---

## What xaidr emits

xaidr writes line-delimited JSON, one event per line, via `FileReporter`:

```python
from xaidr import Sensor
from xaidr.reporters import FileReporter

# native shape
Sensor(agent_id="support-agent", reporter=FileReporter("/var/log/xaidr/events.jsonl"))

# openA2A shape
Sensor(agent_id="support-agent",
       reporter=FileReporter("/var/log/xaidr/events.jsonl", schema="openA2A"))
```

Two shapes, two sourcetypes, because they share **not one field name**:

| | sourcetype | shape |
|---|---|---|
| native | `xaidr:json` | `{"type","agentId","data":{...}}`, nested |
| openA2A | `xaidr:openA2A` | flat, every key a dotted OTel attribute (`gen_ai.security.detection.action`) |

Both are normalised onto a common `xaidr_*` field namespace by this add-on, so a
search written once works against either.

## Install

Drop `TA-xaidr` into `$SPLUNK_HOME/etc/apps/` on your **search head** and restart
(or `| debug refresh`). These are search-time extractions, so they apply to data
already indexed and no re-index is needed.

Set the sourcetype where you collect. For a forwarder tailing the file:

```ini
# inputs.conf, on the forwarder
[monitor:///var/log/xaidr/events.jsonl]
sourcetype = xaidr:json
index = main
```

For HEC, send `"sourcetype": "xaidr:json"` in the event envelope.

## Searches to start from

```spl
sourcetype=xaidr:json xaidr_action=blocked
| stats count by xaidr_agent_id, xaidr_category

sourcetype=xaidr:json xaidr_is_catch=1
| timechart count by xaidr_direction

eventtype=xaidr_degraded
| table _time xaidr_agent_id xaidr_error_type xaidr_scan_id

eventtype=xaidr_circuit_breaker_trip
| table _time xaidr_agent_id xaidr_breaker_reason
        xaidr_breaker_violations xaidr_breaker_tool_calls

sourcetype=xaidr:json xaidr_on_behalf_of=*
| stats values(xaidr_action) by xaidr_on_behalf_of, xaidr_correlation_id
```

---

## Two things to know before you build a dashboard

### 1. Two record types share each sourcetype

`xaidr_event_type` is `scan` or `circuit_breaker`. They are not variations on
one shape:

| | scan | circuit_breaker |
|---|---|---|
| what it is | a verdict on a message | a state transition of the sensor |
| has | action, score, category, rules | transition, reason, counts, thresholds |
| id field | `scanId` | `eventId` |

**A breaker record has no action, no score, no category and no rules**, so a
search written for scans that also matches breaker records does not fail
loudly. It quietly changes its own denominator: `stats count by xaidr_category`
grows a blank row, `avg(xaidr_score)` averages over records that never had a
score, and an events-per-agent panel starts counting circuit flaps alongside
verdicts. Every one of those reads as a data problem rather than a search
problem.

So the verdict-shaped eventtypes in this add-on all state
`xaidr_event_type=scan` explicitly, and `xaidr_is_catch` / `xaidr_is_halting`
are keyed on `xaidr_action`, which a breaker record does not have. Only
`eventtype=xaidr` and `eventtype=xaidr_traced` deliberately match both. If you
write your own searches against `sourcetype=xaidr:*`, scope them the same way.

### 2. The openA2A mapping used to drop breaker events. It does not now

**Fixed in schema 0.2.0.** Under 0.1.0, `to_openA2A` mapped scan fields only and
a `circuit_breaker` event survived as a five-field husk with its reason, counts,
thresholds and trip/close discriminator gone, and nothing on the record to
distinguish it from a scan that had gone empty. `data.traceParent` was dropped
the same way. The old advice here was to ship the native shape if you cared
about breaker visibility; that advice is withdrawn.

A trip now maps in full:

```json
{"gen_ai.security.schema_version":"0.2.0",
 "gen_ai.security.event_type":"circuit_breaker",
 "gen_ai.security.event_id":"ed840f085f26",
 "gen_ai.security.timestamp":"2026-09-01T22:41:26.766832Z",
 "gen_ai.agent.id":"support-agent",
 "gen_ai.security.circuit_breaker.transition":"trip",
 "gen_ai.security.circuit_breaker.reason":"violation_threshold",
 "gen_ai.security.circuit_breaker.violations":2,
 "gen_ai.security.circuit_breaker.tool_calls":0,
 "gen_ai.security.circuit_breaker.violation_threshold":2,
 "gen_ai.security.detection.enforcement_mode":"block"}
```

Both shapes are now equivalent for breaker visibility and trace correlation, and
`eventtype=xaidr_circuit_breaker` works against either.

Three details worth knowing about breaker records:

* **A disabled trigger is absent, not zero.** The emitter omits a threshold
  whose trigger is switched off, because an absent attribute already means
  "unknown" in this schema and a null is what a chart reads as zero. An empty
  `xaidr_breaker_rate_threshold` means the rate trigger is off. Do not
  `fillnull` these.
* **A trip's reason and a close's reason are the same field.** The mapper
  collapses the internal `reason` and `tripReason` onto one attribute, and this
  add-on does the same for the native shape via a calculated field, so a close
  joins back to its trip on equal values.
* **There is no severity on a breaker record**, deliberately. Severity is
  derived from action and score on the scan path, and a breaker has neither, so
  any value would be the emitter's opinion rather than a measurement. Alert on
  `eventtype=xaidr_circuit_breaker_trip` instead.

### Timestamps

Both shapes carry a **scan-time** timestamp: RFC 3339, UTC, microseconds
(`2026-09-01T22:41:26.766832Z`). Both sourcetypes parse it with
`TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6NZ`.

This also changed in 0.2.0, and both halves were wrong before. The native shape
carried no time field at all, so this add-on set `DATETIME_CONFIG = CURRENT` and
event time was receipt time. The openA2A shape had one, but the mapper minted it
at **map** time: mapping runs in the telemetry flush worker, up to
`flush_interval_sec` (5.0 by default) after the scan, mapping a batch of up to
50 events in one pass, so a whole batch received near-identical stamps unrelated
to when anything happened and intra-batch ordering was lost. Whole-second
precision made that worse, since a scan takes well under a millisecond.

---

## Not CIM-mapped, and why

**This add-on does not claim CIM compliance and ships no `tags.conf` and no data
model.** That is a decision, not an omission, and the reasoning is here rather
than left as a blank field.

The plausible target models are Intrusion Detection and Alerts. Neither fits
without inventing data:

* **There is no `src` and no `dest`.** Intrusion Detection requires them and
  every dashboard built on it assumes network endpoints. xaidr's "destination"
  is `llm`, a tool name like `run_command`, or an MCP server URI. Writing a tool
  name into `dest` would populate the data model with values that are not hosts,
  and every `iplocation`, asset lookup and `dest`-keyed panel downstream would
  silently produce nonsense.
* **`action` does not map.** CIM's IDS `action` is essentially allowed/blocked.
  xaidr has four verdicts, and `approval_required` (from a `require_approval`
  policy) has no CIM equivalent. Folding it into `blocked` would erase the
  distinction between "stopped" and "waiting for a human", which is the
  distinction the verdict exists to make.
* **`severity` is ours, and it is tunable.** The openA2A `severity` attribute is
  derived by xaidr from `(action, score)` with cut points the schema source
  describes as trivial to tune later. Binding a tunable to a CIM field freezes
  it into a contract, and if the model is accelerated the old values are already
  in the tsidx when it changes.
* **The schema is bespoke and moving.** `gen_ai.security.*` is at
  `schema_version 0.2.0`, and OCSF alignment is open work that may rename or
  restructure these attributes. A mapping written now would be re-litigated, and
  a *wrong* CIM mapping is worse than none: it is wrong at a distance, inside
  someone else's dashboard, with nothing on screen to say the fields were
  guessed.

The `xaidr_*` namespace is stable and documented below. If your environment has
an answer for what `src` and `dest` mean for an agent action, that answer is
local to you, and a small `tags.conf` plus a few `FIELDALIAS` lines in a local
app will express it better than a guess shipped from here.

Revisit when `gen_ai.security.*` reaches 1.0 or OCSF alignment settles.

---

## Field reference

Every field below was observed in real events generated through `FileReporter`,
not read off a spec. Counts are out of 48 events per shape covering: the
content path in both enforcement modes, the output path, the tool path, MCP,
A2A sent and received, blocked tools, local authz policy (block / approval /
allow), privilege tiers, provenance and delegation, W3C trace context, the
optional nano ML signal, the degraded fail-open path, and circuit-breaker trip
and close on both triggers.

### Common `xaidr_*` fields (both sourcetypes)

| field | native source | openA2A source |
|---|---|---|
| `xaidr_agent_id` | `agentId` | `gen_ai.agent.id` |
| `xaidr_action` | `data.action` | `gen_ai.security.detection.action` |
| `xaidr_score` | `data.score` | `gen_ai.security.detection.score` |
| `xaidr_category` | `data.category` | `gen_ai.security.detection.category` |
| `xaidr_rules` (mv) | `data.rules{}` | `gen_ai.security.detection.rules` |
| `xaidr_direction` | `data.direction` | `gen_ai.security.interaction.direction` |
| `xaidr_enforcement_mode` | `data.enforcementMode` | `gen_ai.security.detection.enforcement_mode` |
| `xaidr_latency_ms` | `data.scanTimeMs` | `gen_ai.security.detection.latency_ms` |
| `xaidr_content_hash` | `data.promptHash` | `gen_ai.security.interaction.content_hash` |
| `xaidr_content_length` | `data.promptLength` | `gen_ai.security.interaction.content_length` |
| `xaidr_destination_type` | `data.destinationType` | `gen_ai.security.interaction.destination_type` |
| `xaidr_destination_id` | `data.destinationIdentifier` | `gen_ai.security.interaction.destination_id` |
| `xaidr_tool_name` | `data.toolName` | `gen_ai.tool.name` |
| `xaidr_impact_class` | `data.impactClass` | `gen_ai.security.authz.impact_class` |
| `xaidr_impact_tier` | `data.impactTier` | `gen_ai.security.authz.impact_tier` |
| `xaidr_authz_decision` | `data.authzDecision` | `gen_ai.security.authz.decision` |
| `xaidr_authz_policy_id` | `data.authzPolicyId` | `gen_ai.security.authz.policy_id` |
| `xaidr_degraded` | `data.degraded` | `gen_ai.security.detection.degraded` |
| `xaidr_error_type` | `data.errorType` | `gen_ai.security.detection.error_type` |
| `xaidr_nano_score` | `data.nanoScore` | `gen_ai.security.detection.nano_score` |
| `xaidr_nano_raw` | `data.nanoRaw` | `gen_ai.security.detection.nano_raw` |
| `xaidr_nano_calibrated` | `data.nanoCalibrated` | `gen_ai.security.detection.nano_calibrated` |
| `xaidr_on_behalf_of` | `data.provenance.on_behalf_of` | `gen_ai.security.provenance.on_behalf_of` |
| `xaidr_actor` | `data.provenance.actor` | `gen_ai.security.provenance.actor` |
| `xaidr_origin_agent` | `data.provenance.origin_agent` | `gen_ai.security.provenance.origin_agent` |
| `xaidr_correlation_id` | `data.provenance.correlation_id` | `gen_ai.security.provenance.correlation_id` |
| `xaidr_delegation_depth` | `data.provenance.delegation_depth` | `gen_ai.security.provenance.delegation_depth` |
| `xaidr_event_type` | `type` | `gen_ai.security.event_type` |
| `xaidr_timestamp` | `data.timestamp` | `gen_ai.security.timestamp` |
| `xaidr_breaker_transition` | `data.event` | `gen_ai.security.circuit_breaker.transition` |
| `xaidr_breaker_reason` | `data.reason` / `data.tripReason` | `gen_ai.security.circuit_breaker.reason` |
| `xaidr_breaker_close_method` | `data.how` | `gen_ai.security.circuit_breaker.close_method` |
| `xaidr_breaker_violations` | `data.violations` | `gen_ai.security.circuit_breaker.violations` |
| `xaidr_breaker_tool_calls` | `data.toolCalls` | `gen_ai.security.circuit_breaker.tool_calls` |
| `xaidr_breaker_violation_threshold` | `data.violationThreshold` | `gen_ai.security.circuit_breaker.violation_threshold` |
| `xaidr_breaker_rate_threshold` | `data.rateThreshold` | `gen_ai.security.circuit_breaker.rate_threshold` |
| `xaidr_breaker_cooldown_sec` | `data.cooldownSec` | `gen_ai.security.circuit_breaker.cooldown_sec` |
| `xaidr_trace_id` | `data.traceParent.traceId` | `trace_id` |
| `xaidr_span_id` | `data.traceParent.spanId` | `span_id` |
| `xaidr_trace_flags` | `data.traceParent.traceFlags` | `trace_flags` |
| `xaidr_trace_source` | `data.traceParent.source` | `gen_ai.security.trace.source` |
| `xaidr_is_catch` | derived | derived |
| `xaidr_is_halting` | derived | derived |
| `xaidr_shape` | derived (`native`) | derived (`openA2A`) |

The openA2A shape emits `trace_id`, `span_id` and `trace_flags` **top-level and
undotted**, matching the OpenTelemetry log data model rather than re-minting
them under `gen_ai.security.*`, so a consumer already joining on those names
does not have to special-case this producer. They are also extracted to the
`xaidr_*` names above so one search works against either shape.

`xaidr_severity` and `xaidr_message` are openA2A-only: the mapper derives them
and the native shape has no equivalent.

`xaidr_scan_id`, `xaidr_event_id`, `xaidr_destination_agent`, `xaidr_mcp_server`,
`xaidr_privilege_tier`, `xaidr_privilege_tier_configured`,
`xaidr_least_privileged_tier`, `xaidr_delegated` and `xaidr_chain_tiers` are
native-only. `xaidr_breaker_trip_reason` is native-only, and is the raw
`data.tripReason` kept beside the collapsed `xaidr_breaker_reason` for anyone
who wants the distinction.

### Observed values

| field | values seen |
|---|---|
| `xaidr_event_type` | `scan`, `circuit_breaker` |
| `xaidr_action` | `allowed`, `flagged`, `blocked`, `approval_required` |
| `xaidr_direction` | `input`, `output`, `tool_call`, `a2a`, `a2a_inbound` |
| `xaidr_enforcement_mode` | `monitor`, `block` |
| `xaidr_destination_type` | `external_api`, `tool_call`, `mcp_server` |
| `xaidr_impact_tier` | `medium`, `high`, `critical` |
| `xaidr_authz_decision` | `allowed`, `blocked`, `approval_required` |
| `xaidr_severity` (openA2A) | `info`, `medium`, `high`, `critical` |
| `xaidr_interaction_type` (openA2A) | `a2user`, `a2a`, `a2tool`, `a2mcp`, `a2llm` |
| `xaidr_breaker_transition` | `trip`, `close` |
| `xaidr_breaker_reason` | `violation_threshold`, `rate_threshold` |
| `xaidr_breaker_close_method` | `manual_reset`, `cooldown_elapsed` |
| `xaidr_trace_source` | `wire`, `otel` |

`xaidr_rules_raw` (openA2A only) holds the rules array as its literal JSON text.
It exists because `xaidr_rules` is built from it in two stages; it is left
exposed rather than hidden because it is occasionally the easier thing to match
on. `xaidr_rules` is the multivalue field you want.

---

## How this was verified

**Verified on a real Splunk 10.4.2 instance**, by indexing the event corpus and
running searches against it. Everything this add-on does — timestamp parsing,
both extraction paths, the aliases, the calculated fields and the eventtypes —
was observed working there. Every item this document previously listed as an
unconfirmed judgement call is settled below, along with one check that was not
on that list and matters more than any of them.

### On the instance (Splunk 10.4.2)

* **Dotted flat keys survive verbatim.** Splunk's JSON extractor names a flat
  key containing dots exactly as written: `gen_ai.security.authz.decision` comes
  through un-mangled, not flattened, split, or rewritten to underscores. This
  was the open question the openA2A extractions were designed around.
* **`%6N` parses.** Splunk's own six-digit subsecond specifier reads the
  microsecond stamp on both sourcetypes. Previously only the equivalent Python
  format had been exercised.
* **`FIELDALIAS` resolves on the native shape.** The `data.action`-style
  path-joined names Splunk generates for nested JSON alias correctly onto the
  `xaidr_*` namespace. These were expected to work from the documented
  behaviour, but had never been run.
* **The `EVAL-` calculated fields compute.** `xaidr_is_catch`,
  `xaidr_is_halting`, `xaidr_shape` and the native `xaidr_breaker_reason`
  coalesce all evaluate, which confirms the order of operations they depend on:
  aliasing runs before calculated fields. Critically, **`xaidr_is_halting`
  diverges from `xaidr_is_catch` on flagged rows** — a flagged verdict is a
  catch but not a halt. The two fields are not accidentally the same
  expression, which is the failure a single all-blocked corpus would hide.
* **No breaker leakage into verdict searches.** `eventtype=xaidr_blocked`
  returned **40 events, every one with `xaidr_event_type=scan`**. The explicit
  `xaidr_event_type=scan` scoping described above holds against real indexed
  data: no circuit-breaker record reaches a search written for verdicts.

That last one is the load-bearing check. A breaker record silently joining a
verdict search is the failure mode this add-on is shaped to prevent, and it is
the one that would never announce itself — it would just move a number.

The remaining item on the old list was the **regex dialect**: these patterns
were authored against Python's `re`, and Splunk runs PCRE. That is now
exercised rather than reasoned about, though by implication rather than by a
dedicated test — the openA2A extractions *are* those regexes, so the results
above could not have been produced unless they ran correctly under PCRE. The
patterns use no construct where the two engines differ (no lookbehind, no
possessive quantifiers, no recursion, no named groups), which is why this was
always the least likely of the five to bite.

### Against the event corpus

Verified against **48 real schema-0.2.0 events per shape** generated through
`FileReporter`, in both shapes. The corpus covers the content path in both
enforcement modes, the output path, the tool path, MCP, A2A sent and received,
blocked tools, local authz policy (block / approval / allow), privilege tiers,
provenance and delegation, W3C trace context, the nano ML signal, the degraded
fail-open path, and **three circuit-breaker records: two trips (both triggers)
and one close**.

* every `transforms.conf` regex, applied in the order `props.conf` chains them,
  with `SOURCE_KEY` honoured, and every extracted value compared to the JSON
  ground truth. **47 stanzas, all 47 referenced by a `REPORT-` chain with no
  orphans**, every field agreeing, no field extracted where the JSON has none.
  All rule names recovered as multivalue.
* `LINE_BREAKER = ([\r\n]+)`: 48 lines per file, each a complete JSON object.
* `TRUNCATE = 100000` against the longest event (1609 bytes).
* `TIME_PREFIX` / `TIME_FORMAT` on **both** sourcetypes: matched, parsed, and
  the parsed span compared to the JSON value, 48 of 48 each. Stamp is 27 bytes
  against `MAX_TIMESTAMP_LOOKAHEAD = 32`. `[xaidr:json]` confirmed to no longer
  set `DATETIME_CONFIG`.
* the breaker path end to end: transition, reason, close method, counts and
  thresholds all extracted; **no verdict field present on any breaker record**;
  a close joining back to its trip on an equal `xaidr_breaker_reason`; and a
  disabled trigger staying absent rather than materialising as zero.
* over-match probes: `detection.score` does not match `detection.nano_score`,
  `detection.latency_ms` does not match `interaction.content_length`,
  `circuit_breaker.violations` does not match `circuit_breaker.violation_threshold`,
  and the anchored `span_id` / `trace_id` patterns do not match `parent_span_id`
  or `x_trace_id`.
* every field an eventtype searches on is one this add-on actually produces.
* `splunk-appinspect` on the packaged tarball: 0 errors, 0 failures, 0 warnings,
  0 manual checks, 0 skipped, on both the cloud tag set and the full set.

### The openA2A extractions could become aliases. They are correct either way

The openA2A fields are extracted with `REPORT-` regexes against the raw event
text rather than with `FIELDALIAS` entries, because when they were written it
was not known what Splunk would name a flat key containing dots. A regex is
correct whichever way that lands; an alias is only correct if the extractor
produces the literal dotted name.

It does. `gen_ai.security.authz.decision` is preserved verbatim on 10.4.2, so
**a future version could express most of these as `FIELDALIAS` entries** and
delete a large share of `transforms.conf`. That would be less configuration
doing the same work, and aliases are cheaper than a regex pass over the raw
text on every matching event.

This is a simplification, not a correction. **The regexes are correct as they
stand and are verified as they stand** — they are what produced the results
above. Nothing here is waiting on a fix, and there is no reason to hold off
deploying this version. The change is worth making when there is a reason to
touch these files anyway, and it wants its own verification pass on the
instance when it happens, because `FIELDALIAS` and `REPORT-` do not run at the
same point in the search-time pipeline.

The `FIELDALIAS-xaidr_a2a_core` line already present is the convenience path
for exactly these names, and is redundant with the regexes rather than in
conflict with them.

### What is still not measured

* **Splunk versions other than 10.4.2.** One instance, one version. Nothing
  here is known to be version-sensitive — see the note on the version floor in
  `app.manifest` below — but "works on 10.4.2" is the claim, and it is the only
  one supported by evidence.
* **Scale.** The corpus is 48 events per shape. Extraction correctness does not
  depend on volume, but search performance at production cardinality was not
  measured.

### A version floor is deliberately not declared

`app.manifest` declares no minimum Splunk version, and that is a decision.

This add-on is parsing configuration: `props.conf`, `transforms.conf`,
`eventtypes.conf`, and no code at all. Every construct it uses — `REPORT-`,
`FIELDALIAS-`, `EVAL-`, `LINE_BREAKER`, `KV_MODE`, `TIME_FORMAT` — has been in
Splunk for many major versions. There is no call here that an older search head
would not understand, so there is no measured incompatibility to encode.

A floor is an install-time refusal, and for a config-only add-on that is the
wrong shape of failure. If some older version did mis-handle one construct, the
result is a degraded field, which is legible and searchable. Refusing to
install instead costs the operator every `xaidr_*` field to protect them from
losing one.

Declaring `>= 10.4` would also be false: it would block search heads where this
almost certainly works, on the strength of never having tried. Declaring
`>= 9.0` or `>= 8.0` would be worse — a boundary asserted from no measurement
at all, which is the same failure this document refuses elsewhere when it
declines to guess a CIM mapping.

So: the verified-good version is recorded here, in prose, where it is honest.
Revisit if an actual incompatibility is observed on a specific version, and
encode *that* version, measured.

### Searches used

```spl
sourcetype=xaidr:openA2A
| table _time xaidr_event_type xaidr_action xaidr_score xaidr_rules
        xaidr_is_catch xaidr_is_halting xaidr_shape

eventtype=xaidr_blocked
| stats count by xaidr_event_type

eventtype=xaidr_circuit_breaker
| table _time xaidr_shape xaidr_breaker_transition xaidr_breaker_reason
        xaidr_breaker_close_method xaidr_breaker_violations
```

---

## Pre-0.2.0 data

Events indexed before the xaidr release that added schema 0.2.0 are shaped
differently, and this add-on does not pretend otherwise.

**openA2A.** Those events carry a whole-second timestamp, which `%6N` will not
parse; Splunk falls back to automatic recognition, which does read a bare
ISO 8601 string, so they still land at roughly the right time. They carry no
`gen_ai.security.event_type`, so `xaidr_event_type` is empty and
`eventtype=xaidr_scan` will not match them. Any breaker record among them is the
five-field husk the old mapper produced: no reason, no counts, no transition.
Nothing can recover those, because they were never written. This is named so it
is not mistaken for a parsing failure.

**native.** Those events carry no timestamp at all, so `TIME_PREFIX` will not
match and Splunk's automatic recognition has nothing date-like to find on this
shape. It may guess badly from a hash fragment or an integer.

No legacy sourcetype ships for this, deliberately: a clone carrying only
`DATETIME_CONFIG = CURRENT` would fix the timestamp and silently drop every
`xaidr_*` field, because Splunk has no props inheritance and the native
extractions are `FIELDALIAS` entries bound to `[xaidr:json]`. A sourcetype that
times events correctly and extracts nothing is a worse trap than a documented
caveat. If you hold meaningful pre-0.2.0 native volume, `props.conf` in this
add-on carries the four-line recipe for a local `[xaidr:json:legacy]` stanza and
tells you which block to copy into it.

---

## Two notes on reading these events

**Content is never in the event.** xaidr hashes scanned text before telemetry;
`xaidr_content_hash` is a 16-hex-character digest and there is no field
containing the prompt, the tool arguments or the model output. A search for
message text will not find one.

**`xaidr_nano_score` is not confidence.** When the optional ML signal
contributes, the event carries `xaidr_nano_calibrated=false` beside the number,
because the model rates innocuous text highly at a measured rate and the emitter
attaches the caveat so it arrives with the value. Do not sort an alert queue by
`xaidr_nano_score`. The verdict is in `xaidr_action`.

---

## Building the package

```sh
python3 integrations/splunk/build_ta.py     # -> dist/TA-xaidr.tar.gz
```

The build is reproducible: the same source tree gives the same sha256 on any
machine, in any checkout. That is not automatic and it took three pins to get.
`gzip` stamps the compression time into its header; tar records a per-file
mtime, which a fresh `git clone` sets to checkout time; and `os.walk` order,
uid and gid otherwise leak the builder's environment into the archive. The
script pins all three. The middle one is the trap, because rebuilding from a
tree you already have preserves mtimes and the hash looks stable right up until
CI clones fresh.

Set `SOURCE_DATE_EPOCH` to override the pinned timestamp.

## Support

Issues: https://github.com/delphisecurity/xaidr/issues

## License

Apache License 2.0. See `LICENSES/Apache-2.0.txt`.
