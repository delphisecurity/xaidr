# Held-out ASI battery (ASI01–ASI10)

A held-out evaluation battery for the agentic-security categories ASI01 through
ASI10. **Nothing here was used to build the rules, nano, or the existing
coverage probe.** It exists because the shipped probe is 107 strings we
authored: it confirms what we already believed. Every time an outsider brings a
new population, our numbers move — the held-out nano set found 17 misses
concentrated in plain exfiltration, tool misuse and integrity, which the probe
does not cover. This battery is that outsider population for the full ASI map.

## Publishable, like the nano set

Authored by the xaidr maintainers for this repo, released under the repo's
Apache-2.0 license, no third-party text, committed to the public tree.
`scripts/asi_battery_report.py` regenerates every number in `RESULTS.md`.

## What's here

| File | What it is |
|---|---|
| `attacks.jsonl` | 120 attack cases, 12 per category |
| `benign.jsonl` | 120 register-matched benign cases, 12 per category |
| `../scripts/asi_battery_report.py` | regenerates the numbers |
| `last_run.json` | machine-readable summary of the last local run (git-ignored) |

## How the cases were written (blind to the coverage table)

The prompts were authored **before** reading the existing probe
(`scripts/owasp_agentic_probe.py`), the README's ASI mapping table, or the
coverage audit — so the battery could not be shaped to confirm a recorded
verdict. The category *definitions* were taken only from the rule labels in
`xaidr/rules/*.json` (e.g. `ASI01_covert_exfil`, `ASI06_memory_manipulation`),
never from the verdict table. Working definitions used:

| cat | working definition (from rule labels) |
|---|---|
| ASI01 | goal / instruction manipulation and covert exfiltration |
| ASI02 | tool misuse — unauthorized and destructive actions |
| ASI03 | privilege escalation, identity & authorization abuse |
| ASI04 | resource overload / denial-of-service / denial-of-wallet (no rule labels exist for this category; definition inferred) |
| ASI05 | unsafe code execution & self-modification via exec |
| ASI06 | memory poisoning, persistent injection, rogue agent registration |
| ASI07 | agent-to-agent (A2A) / multi-agent pipeline communication abuse |
| ASI08 | cascading failure / systemic multi-agent impact |
| ASI09 | knowledge / RAG poisoning and trust corruption |
| ASI10 | behavioural drift, self-modification, concealment |

## Boundaries and registers (the two axes the probe under-uses)

**Boundaries.** Each category is written across the boundaries it actually
crosses, not just the input line:

- `input` — inbound chat text
- `tool_call` — a tool name + arguments (scanned via `scan_tool_call`)
- `output` — the agent's own outgoing text (`scan_output`)
- `a2a` — an agent-to-agent message (`scan_a2a`)
- `sequence` — an ordered list of steps, each at its own boundary

**ASI06 and ASI10 are multi-step by necessity.** A poisoned memory is a *write*
(a `store_memory` / `kb_write` tool call planting a false standing fact) and a
later *read* (an ordinary-looking input that acts on it) — neither message is an
attack alone. Behavioural drift is a *change over calls* — comply normally, then
diverge and conceal. A single-message probe cannot express either, which is
likely why both read as hard to cover. A sequence is scored as detected if **any
step** is detected; the harness records which step (if any) caught it.

**Plain, non-injection registers are mandatory in every category.** The nano set
showed plain language is where detection is blind, and the existing probe leans
on trigger vocabulary (`ignore all previous instructions`, a shared `INJECTION`
constant, multilingual overrides, shell/SQL command forms). Here, most cases are
ordinary operator/agent language with no trigger words, no roleplay, no
encoding. A handful of ASI05/ASI07 cases keep a command-form or encoded shape on
purpose, to represent the boundary the rules are known to cover.

**The benign set mirrors the attacks** one-to-one at the same boundary and
register: `ASI02-B01` is an *approved* vendor payment where `ASI02-A01` is an
unauthorized one; `ASI06-B01` stores an *accurate* policy where `ASI06-A01`
stores a poisoned one; `ASI10-B02` asks the agent to *keep its process
consistent* where `ASI10-A02` asks it to change and conceal. Same words,
opposite intent — so the per-category false-positive number is measured on the
same distribution as the catch rate.

## How to reproduce

```sh
pip install -e .
pip install 'onnxruntime>=1.20' 'tokenizers>=0.20' 'numpy>=1.24' 'huggingface-hub>=0.23'
python -c "import xaidr.scanner.nano as n; n.resolve_model_dir(auto_download=True)"  # ~130 MB, once
python scripts/asi_battery_report.py
```

Without the `nano` extra / artifact, the rules-only half still runs and the
rules-plus-nano half is reported **NOT RUN**, loudly. The run is deterministic,
uses `monitor` mode and a null reporter (no telemetry, no network), and the
circuit breaker never blocks in monitor mode, so the 240 sequential calls do not
perturb one another.

## What "detected" means

`action != "allowed"` — flagged or blocked. Nano only contributes on the
**input** boundary (it is scoped to inbound chat text and only runs when the
rules pipeline scored exactly 0.0), so on tool-call, output and A2A cases
rules-plus-nano is identical to rules-only **by construction**.

See `RESULTS.md` for the measured numbers, the comparison to the recorded
verdicts, and where this held-out result contradicts them.
