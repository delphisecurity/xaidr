# Benchmarks

What was tested, on what machine, and what came out. Nothing else.

These are one machine's numbers. Yours will differ, and hardware variance is
material rather than cosmetic, so the script is in the repository and running it
is the answer to "but what about mine":

```bash
python scripts/benchmark.py
```

Every figure on this page comes from a single run of that script, plus one run
each of `scripts/intent_metrics.py` and `scripts/corpus_report.py`, all
performed against this working tree.

## The machine

| | |
|---|---|
| platform | `macOS-26.3.1-arm64-arm-64bit` |
| machine | `arm64` |
| processor | `arm` |
| cpu count | 10 |
| python | CPython 3.12.2 |
| package | `/Users/anirudhkotaru/opena2a/xaidr/__init__.py` (the repository tree, not an installed copy) |
| version | 1.4.1 |

## What was tested

Seven shapes of ordinary agent traffic, one timed call each per pass:

| boundary | shape | payload |
|---|---|---:|
| scan_tool_call | read_file, short path | 9 B |
| scan_tool_call | run_command, benign | 18 B |
| scan_tool_call | run_command, destructive | 20 B |
| scan input | short user prompt | 43 B |
| scan_tool_call | run_sql, bounded delete | 45 B |
| scan_a2a | small delegation envelope | 61 B |
| scan_output | brief model answer | 113 B |

This is deliberately weighted to small messages, because that is what agent
traffic is. One of the seven is attack-shaped, on purpose: a scan that finds
something does more work than one that does not, and a mix of only clean traffic
would flatter the result.

## Headline

Seven shapes, 100 passes each, so 700 timed calls per repeat, three repeats. All
three are shown, because the run-to-run spread is part of the answer:

| repeat | median | p95 | p99 | max | n |
|---|---:|---:|---:|---:|---:|
| #1 | 0.44 | 0.60 | 0.69 | 0.88 | 700 |
| #2 | 0.43 | 0.57 | 0.65 | 0.78 | 700 |
| #3 | 0.43 | 0.57 | 0.62 | 1.28 | 700 |

**Median 0.43 ms, p95 0.57 ms, p99 0.62 ms**, taking the best of the three
repeats. The three agree to within 0.01 ms at the median and 0.03 ms at p95, so
on this machine the figure is stable rather than cherry-picked. The 1.28 ms max
in repeat #3 is one sample out of 700 and is what a garbage collection looks
like; it is left in because the methodology below says collections land in the
numbers.

Per shape, last repeat:

| shape | median | p95 |
|---|---:|---:|
| read_file, short path | 0.15 | 0.17 |
| run_command, destructive | 0.41 | 0.44 |
| short user prompt | 0.41 | 0.43 |
| run_sql, bounded delete | 0.42 | 0.45 |
| brief model answer | 0.45 | 0.47 |
| run_command, benign | 0.55 | 0.61 |
| small delegation envelope | 0.56 | 0.60 |

## False positives, beside detection

A detection rate on its own means nothing, because a detector that blocks
everything scores 100%. Both halves, from one run of each script against the
committed corpus at `tests/fixtures/shell_corpus.json`:

```bash
python scripts/intent_metrics.py     # the catch rate and its denominator
python scripts/corpus_report.py      # the raw counts and the benign gates
```

**Detection.** A catch is `blocked` **or** `flagged`, and the denominator is the
attacks we intend to catch — the corpus minus the 95 entries marked
`detection_intent: INTENDED`, which are recognised, genuinely dual-use, and
deliberately left to a policy the deployer writes. Every one of those 95 carries
its reason in the fixture, and `intent_metrics.py` prints them all before it
prints a percentage.

| | denominator | catches |
|---|---:|---|
| rules only, tool path | 186 | **165** (88.7%) |
| rules only, content path | 186 | **105** (56.5%) |
| rules only, either path | 186 | **167** (89.8%) |
| with `nano`, either path | 186 | **172** (92.5%) |

**Raw counts, unchanged, from `corpus_report.py`.** These are the evidence and
they stay. They are *not* a detection rate: `blocked / 281` counts every
deliberately classify-only entry as a failure, which is why it is no longer
published as one.

| | n | result |
|---|---:|---|
| shell attacks classified | 281 | **267** |
| shell attacks detected (score > 0) | 281 | **165** |
| shell attacks blocked | 281 | **165** |

**False positives, same run, same sensor.**

| | n | result |
|---|---:|---|
| benign commands scoring above zero | 74 | **0** |
| benign commands blocked | 74 | **0** |
| benign prose blocked, content path | 89 | **1** (`bp-055`, documented by ID in `tests/test_benign_prose.py`) |
| benign prose blocked, tool-argument path | 89 | **0** |
| benign prose **flagged**, content path | 89 | **50** (56 with `nano` on) |
| benign prose **flagged**, tool-argument path | 89 | **43** |
| benign templates blocked, either path | 12 | **0** |
| benign templates flagged, either path | 12 | **0** (1 with `nano` on) |
| ordinary DevOps operations blocked or flagged | 38 | **0** |
| real benign prompts flagged, rules only | 2000 | **0** (0.00%) |
| real benign prompts flagged, `nano` on | 2000 | **37** (1.85%, Wilson 95% [1.35%, 2.54%]) |

So the false-block rate to read beside 167 of 186 is **0 of 74** on commands,
**1 of 89** on prose, **0 of 12** on templates and **0 of 38** on ordinary
DevOps operations. The one prose blocker is named rather than absorbed into a
percentage, so a second one shows up as a new entry instead of as a rounding
change. Both benign gates are asserted, and `corpus_report.py` exits non-zero if
either is violated.

**But read the flag rows.** The catch rate counts a flag as a catch, so this side
has to count a flag as a false positive, and the honest pairing is: benign prose
— incident reports, runbooks and policy documents that *quote* a dangerous
command — blocks at 1 of 89 and **flags at roughly half**. Those flags are the
design working: the passage surfaces for review and nothing is interrupted, which
is why the committed gate is blocking-only. They are also the price of the
headline number. If your deployment only acts on blocks, the figure to read is
the tool-path block count, not the combined catch rate. An agent whose job
includes reading security documents will generate flag volume at that rate;
see [monitor mode](README.md#deployment-modes-and-tuning). Everything else —
commands, templates, ordinary DevOps operations — is 0 on both columns.

The 2000-prompt rows were measured on **xaidr 1.7.0 with onnxruntime 1.29.0**
with `python scripts/intent_metrics.py --nano --real-benign`. The sample is
pinned **by identity**, not by a seed: `tests/fixtures/nano_fp_sample.json` names
2000 prompts by SHA-256 and the script rebuilds them from dolly / no_robots /
oasst1 at run time (hashes rather than text because no_robots is CC-BY-NC-4.0).
It is the sample the model acceptance used, and it is disjoint from the prompt
sets the model was selected and calibrated against.

**This quantity had three published values and now has one.** 1.85% is the
acceptance record's own figure and is what the shipped configuration reproduces
today, prompt for prompt. **2.20% (44/2000) is withdrawn and was wrong, not
merely stale**: the acceptance evidence file stores each prompt truncated to 200
characters as a preview, 331 of the 2000 are longer, and the re-measurement that
produced 2.20% scored the previews — feeding the 200-character cut through the
current runtime moves the count 37 → 43 on its own, which is the entire gap that
was previously attributed to onnxruntime drift. **1.65% (33/2000) is withdrawn**
as a different sample: a freshly drawn seeded one overlapping this by 128 of
2000 and not disjoint from the tuning sets, which biases the rate downward.
Runtime drift is real — 15 of 2000 raw scores differ from the record on 1.29.0 —
but only 2 cross the operating point and they cross in opposite directions, so
the figure is 37/2000 either way. Treat that as this sample being lucky.

**This figure rests on public datasets that a public model may have seen.** We
did not train the nano model; that its authors' stated training mix excludes
these three datasets is their statement, not something we verified, and
contamination cannot be ruled out.

The prose corpus is 89 passages in three groups. The first is 66 that quote a
SHELL COMMAND. The second is 7 (`bp-067`..`bp-073`) that carry a MODEL-DIRECTED
payload — a named-persona jailbreak, a developer-mode request, a system-prompt
extraction turn, an encoding-evasion payload, a rate-limit log that reads as
denial of service, and a forged tool result. That second group exists because the
first cannot exercise the
five families the 1.2.0 tool-argument scan newly admitted at flag level: every one
of the 66 is a shell quotation, so the tool-path prose gate read 0 of 66 by never
being tested on them. Each of the 7 carries its payload in plain prose rather than
inside backticks, because the documentary-prose cap only lifts fenced quotations
and the uncapped case is the one at risk. All 7 reach their family (score 0.48 to
0.96 as a tool argument) and flag rather than block; the assertions that they
score above zero live in `tests/test_benign_prose.py` so the gate cannot go
vacuous again.

A third group of 16 (`bp-074`..`bp-089`) is BENIGN INVERSIONS: ordinary prose
that uses safety-negation reframing vocabulary with no attack in it — a staging
rule that is reversed, an approval flow that runs the other way, a boolean
inverted against its flag, a policy section explaining when not to comply. They
were written to price a candidate fix for the "opposite day" reframing family,
and they found a live false positive instead: `LLM01_encoded_instruction` matched
a bare `backwards|reversed` plus any ten characters, so 6 of the 16 BLOCKED on
the tool-argument path, where `prompt_injection` is a block-tier category. No
corpus entry contained the word, so the rule had never been measured — the whole
suite passes with it deleted outright. It is now narrowed to the
colon-introduced payload-label form it was written for (`reversed: <payload>`),
which is what every other rule in that family already requires. Each entry
records which of the compositional layer's slots it fills, and the two that fill
all three (`bp-086`, `bp-089`) are asserted to reach the layer under the full
conjunction an inversion attack generates and still score zero — the same
non-vacuity discipline as the group above. See
`tests/test_inversion_reframing.py`, which also records why the compositional
layer was NOT changed.

Reported by family and not per command, the same discipline the README's
[Coverage and limitations](README.md#coverage-and-limitations) section follows.
Read that section for what 167 of 186 does and does not mean — in particular,
which 95 attacks are excluded from that 186 and why.

**What none of these numbers cover.** The corpus is shell commands. It says
nothing about prompt-shaped attacks, nothing about the A2A path, and nothing
about the output boundary; those have their own tests and their own gaps, and
this figure must not be quoted as if it spoke for them. The content-path row is
also a synthetic case for shell — in a real agent the command arrives as a tool
argument, so the tool-path row is the operational one.

## Methodology

* 20 warmup calls per shape, discarded, so import and regex compilation are not
  counted
* one `time.perf_counter()` pair around one sensor call
* nearest-rank percentiles over every sample. No trimming, no outlier removal
* garbage collection left on. Collections land in the numbers
* null telemetry reporter, so no emit cost is inside the numbers
* single process, single thread, no concurrency, no network

## Reproducing the detection table, from scratch

Nothing here should be taken on trust. The whole detection table is one command,
and it prints the denominator and its definition above the percentage:

```bash
python scripts/intent_metrics.py                        # rules only
python scripts/intent_metrics.py --nano                 # + the ML signal
python scripts/intent_metrics.py --nano --real-benign   # + the published FP figure
```

The first two are deterministic: three consecutive runs are byte-identical, and
they were checked that way. The third needs `huggingface_hub` and `pandas`,
downloads the three public datasets, and rebuilds the pinned 2000-prompt sample
by hash; it fails loudly rather than reporting a number from a short sample if
an upstream snapshot has moved.

To confirm the numbers are a property of the shipped package and not of this
working tree, install the published wheel into a fresh virtualenv and point the
script at it from an unrelated directory. `--installed` is what stops the script
shadowing site-packages with the checkout; the fixture still comes from the
checkout, because it is not in the wheel:

```bash
python -m venv /tmp/xaidr-verify
/tmp/xaidr-verify/bin/pip install 'xaidr[nano]==1.7.0'
cd /                                                  # a neutral working directory
/tmp/xaidr-verify/bin/python /path/to/xaidr/scripts/intent_metrics.py --installed --nano
```

Done on **published 1.7.0, Python 3.14, onnxruntime 1.29.0**, the
output below the provenance header is byte-identical to the working-tree run.

## Getting your own

```bash
python scripts/benchmark.py
```

It prints the machine at the top of its own output, asserts nothing, and gates
nothing. If your numbers differ from the ones here, yours are the ones that
matter for your deployment.

---

Larger inputs cost more, and the cost is dominated by the regex layer, which
scales with byte count: 200 B of prose scans in about 2.3 ms on the input path
and 256 KB in about 1.4 s. Distinct vocabulary adds a second, much smaller term,
so a varied paragraph costs somewhat more than a repetitive one of the same
length. The internal scan cap means very large inputs are bounded rather than
unbounded. The script's size sweep measures all of this if you need it.

See [THREAT_MODEL.md](THREAT_MODEL.md) for what these controls do and do not
defend against.
