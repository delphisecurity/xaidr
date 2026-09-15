# Benign nested A2A corpus

60 benign A2A JSON-RPC bodies that between them populate **every container the
A2A spec says can hold a Message, a Part or an Artifact**. It exists to measure
the false-positive cost of walking those containers, because until it existed
that cost could not be measured at all.

## Why this corpus

The A2A structural validator used to read only the top-level message. Reaching
nested messages means walking attacker-controlled structure and scanning
strictly more values, which is strictly more chances to misfire. The obvious
move is to measure the delta on the committed benign pools.

**That measurement is vacuous.** Instrumenting
`A2AStructuralValidator.validate` across `asi_battery/`, `heldout/` and
`benign_toolcalls/` gives:

```
items scanned                         : 228
  of which routed to scan_a2a         : 42
A2AStructuralValidator.validate calls : 0
```

The 42 items those pools send through `scan_a2a` are **plain text**. The body
never parses to a dict, so the structural layer never runs. A false-positive
delta of zero across every committed pool — which is what this change measures,
all 1139 `corpus_diff` rows byte-identical — says nothing about this code,
because none of those rows reach it.

That is the blind-population problem: a gate that passes on a population the
change cannot touch reads as coverage while performing none. This corpus is the
population.

## What's here

| File | What it is |
|---|---|
| `nested.jsonl` | 60 benign A2A bodies, full JSON-RPC envelopes |
| `../scripts/benign_a2a_report.py` | regenerates the numbers below |
| `../tests/test_f6_a2a_nested_containers.py` | asserts the gate in the suite |

Each entry records `persona`, `shape`, `container` (which nested placement it
exercises), `why_benign`, and the full `body`.

## Container coverage

Every placement in the canonical spec — `specification/a2a.proto` @ v1.0.1 and
the v0.3.0 JSON Schema, which agree field-for-field — appears here:

| Container | Spec field | Entries |
|---|---|---|
| `params.message` | `MessageSendParams.message` | NA2A-028, -029 |
| `result` (bare Message) | `SendMessageResponse.result` | NA2A-032 |
| `result.status.message` | `TaskStatus.message` | NA2A-001, -002, -005, … |
| `result.history[]` | `Task.history[]` | NA2A-003, -004, -013, … |
| `result.artifacts[]` | `Task.artifacts[]` | NA2A-006, -007, -014, … |
| `result.artifact` | `TaskArtifactUpdateEvent.artifact` | NA2A-011, -012 |
| `result.status` (streaming) | `TaskStatusUpdateEvent.status` | NA2A-009, -010, -060 |
| `result.tasks[]` | `ListTasksResponse.tasks[]` | NA2A-026, -027 |
| `result.task` | impl-side Task wrapper | NA2A-058 |
| root (bare Task / Message) | in-process shapes | NA2A-030, -031 |

## What it deliberately contains

A benign corpus that avoids the shapes a detector fires on measures nothing. So
these are in it on purpose:

- **Namespaced ids with a single slash** (`AGENT-SVC/close-books`,
  `tenant/acme/fy2026`, `billing/msg/4471`) — the false-positive crux for the
  id-traversal check, now reached on nested nodes too (NA2A-022, -008).
- **Filesystem paths and stack frames in prose** (`/opt/app/ingest/worker.py`,
  `/tickets/2026/02/T-48213`) — a path in CONTENT is not a path in an id
  (NA2A-047, -057).
- **Long artifact text** — 400+ characters of legitimate summary, to check the
  prose-surface rule stays scoped to `metadata`/`extensions` (NA2A-019).
- **Three-level nested metadata** with short routing values (NA2A-048, -018).
- **A 24-turn history and a 12-part message** — under, but near, the list bounds
  (NA2A-035, -036).
- **v1.0 parts with no `kind` discriminator**, including `data` and `url` arms
  (NA2A-042, -043, -044).
- **Refusals and failures** in nested status messages, which read like the
  attacks they are not (NA2A-046, -059).

## The gate

Zero structural signals on all 60. Not "few". A benign body has no structural
anomaly by construction, so any signal here is a false positive.

```
$ python scripts/benign_a2a_report.py
BENIGN NESTED A2A CORPUS  -  structural false positives   (n=60)
corpus            : benign_a2a/nested.jsonl
A2A nodes walked  : 274  (mean 4.6 per body)
node kinds        : artifact=21, container=117, envelope=58, message=78

persona          n    structural FP
code-review       4      0
data             11      0
devops           15      0
finance           7      0
research          9      0
support          14      0
TOTAL            60      0

BENIGN NESTED A2A GATE: PASS   gate: structural FP must be 0, got 0
```

**274 nodes walked, 99 of them Messages and Artifacts.** That number is the
point: the pre-change validator reached 60 of them (one top-level object per
body). The gate is measured on the population the change actually altered.

`tests/test_f6_a2a_nested_containers.py` asserts both halves — that every entry
is clean, and that the corpus still reaches at least 90 message/artifact nodes.
A corpus that drifted back to top-level-only bodies would keep passing the first
assertion while measuring nothing, so the second one exists to catch that.
