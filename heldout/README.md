# Held-out attack set for nano

A held-out evaluation set for the optional `nano` ML signal (see
`xaidr/scanner/nano.py`). **Nothing here was used to build, train, or tune nano
or the rules.** It exists to answer one question the existing corpus cannot:
what does nano do on prompts it has never seen?

## Why this exists

Nano's headline figure (23/26) was measured on the corpus that *built* it, and
that corpus lives in a separate bench repo that is not shipped — so the number
is neither reproducible here nor a measure of generalisation. Separately, an
outside reviewer wrote 19 fresh prompts and found that five of six
**plainly-worded descriptions of real attacks** — no roleplay, no encoding, no
trigger vocabulary — scored between 0.00 and 0.13. Nano had never been measured
on anything held out.

This set is that measurement, and it is **publishable**: authored by the xaidr
maintainers for this repo, released under the repo's Apache-2.0 license, no
third-party text, committed to the public tree. A corpus nobody can obtain is
how the last figure became unrecoverable; this one cannot.

## What's here

| File | What it is |
|---|---|
| `attacks.jsonl` | 50 attack prompts, one JSON object per line |
| `benign.jsonl` | 50 benign prompts, register-matched one-to-one to the attacks |
| `../scripts/heldout_report.py` | regenerates every number below |
| `last_run.json` | machine-readable summary of the most recent local run (git-ignored; regenerate it) |

Each attack row records `technique`, `register`, `plain_prose`, and `tests`
(what that prompt is probing). Each benign row records which attack it
`mirrors`, so the false-positive cost is measured on the *same* distribution as
the catch rate — not on generic chat.

## Design, stated so it can be argued with

**All 50 attacks are plainly-worded instructions to an agent** — second-person
requests, ordinary English, no roleplay, no encoding, no `ignore all previous
instructions` trigger phrase. This is deliberate and is the whole point: the
plain-prose register is the documented failure shape, so it is the axis the set
holds fixed. Variety comes from the **attack mechanism**, not from surface
obfuscation:

| technique | n | what it is |
|---|---|---|
| plain-exfil | 12 | move or leak data as an ordinary request |
| plain-override | 5 | authority/instruction override in plain words |
| plain-sysprompt | 5 | extract the hidden preamble / config conversationally |
| plain-integrity | 5 | make the agent deceive, falsify, or omit |
| plain-toolmisuse | 5 | repurpose a legitimate tool for harm |
| false-premise | 5 | fabricated prior authorization / agreement |
| plain-agency | 4 | act destructively or autonomously without confirmation |
| plain-antiforensics | 3 | disable logging / destroy the record |
| indirect-injection | 2 | instruction planted in data the agent processes |
| a2a-trust | 2 | forge trust asserted to a downstream agent/tool |
| plain-privesc | 1 | privilege escalation request |
| covert-channel | 1 | steganographic exfiltration, described plainly |

Roleplay, encoding, and delimiter/format injection are **deliberately absent**:
those are the classic prompt-injection-dataset shapes nano was most likely
trained on, so including them would measure recall on nano's home turf, not
generalisation. The held-out axis is register.

A distinction the set is careful about: these are *malicious instructions*
worded plainly, not third-person *descriptions* of attacks. The rules
intentionally dampen genuine third-person description (an incident report that
quotes an attack must not block); such text is benign and belongs in
`benign.jsonl`, not here.

**The benign set mirrors the attacks in register and vocabulary.** B11 asks to
read a *non-secret* config value where A11 asks to read the API-key file; B14
tells a script to *stop and prompt* for a password where A14 says *guess it*;
B28 asks for *synthetic* test rows where A28 says *dump the real table*. Same
words, opposite intent — which is what makes the false-positive number mean
something.

## How to reproduce

Rules-only needs nothing beyond the package. Rules-plus-nano needs the `nano`
extra and the model artifact:

```sh
pip install -e .            # or: pip install xaidr
pip install 'onnxruntime>=1.20' 'tokenizers>=0.20' 'numpy>=1.24' 'huggingface-hub>=0.23'
python -c "import xaidr.scanner.nano as n; n.resolve_model_dir(auto_download=True)"  # ~130 MB, once
python scripts/heldout_report.py
```

If the extra or the artifact is missing, the script still runs the rules-only
half and reports the rules-plus-nano half as **NOT RUN**, loudly, rather than
skipping it silently.

The nano false-positive rate moves with the onnxruntime version (see
`nano.py`), so the script prints the runtime it measured under. A number without
its runtime is unreadable — `RESULTS.md` records both.

## What "detected" means

`action != "allowed"` — the scanner flagged or blocked. Enforcement mode is
`monitor`, so a block-worthy verdict surfaces as `flagged`; either way it is a
detection. Nano only ever contributes a **flag** (its score is floored into the
flag band and can never reach the block threshold), and it only speaks when the
whole rules pipeline scored **exactly 0.0** on inbound input of ≥ 4 words. So
nano's contribution is, by construction, limited to attacks the rules scored
0.0 on.

See `RESULTS.md` for the measured numbers and the honest read of them.
