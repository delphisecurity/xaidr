# Benchmarks

What was tested, on what machine, and what came out. Nothing else.

These are one machine's numbers. Yours will differ, and hardware variance is
material rather than cosmetic, so the script is in the repository and running it
is the answer to "but what about mine":

```bash
python scripts/benchmark.py
```

Every figure on this page comes from a single run of that script, plus one run
of `scripts/corpus_report.py`, both performed against this working tree.

## The machine

| | |
|---|---|
| platform | `macOS-26.3.1-arm64-arm-64bit` |
| machine | `arm64` |
| processor | `arm` |
| cpu count | 10 |
| python | CPython 3.12.2 |
| package | `/Users/anirudhkotaru/opena2a/xaidr/__init__.py` (the repository tree, not an installed copy) |
| version | 1.1.0 |

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
| #1 | 0.39 | 0.56 | 0.61 | 0.93 | 700 |
| #2 | 0.43 | 0.62 | 0.69 | 0.80 | 700 |
| #3 | 0.40 | 0.57 | 0.61 | 0.72 | 700 |

**Median 0.39 ms, p95 0.56 ms, p99 0.61 ms**, taking the best of the three
repeats. The three agree to within 0.08 ms at every percentile, so on this
machine the figure is stable rather than cherry-picked.

Per shape, last repeat:

| shape | median | p95 |
|---|---:|---:|
| read_file, short path | 0.13 | 0.16 |
| run_sql, bounded delete | 0.35 | 0.38 |
| short user prompt | 0.38 | 0.42 |
| run_command, destructive | 0.39 | 0.43 |
| brief model answer | 0.44 | 0.49 |
| run_command, benign | 0.51 | 0.59 |
| small delegation envelope | 0.55 | 0.60 |

## False positives, beside detection

A detection rate on its own means nothing, because a detector that blocks
everything scores 100%. Both halves, from one run of `scripts/corpus_report.py`
against the committed corpus at `tests/fixtures/shell_corpus.json`:

```bash
python scripts/corpus_report.py
```

| | n | result |
|---|---:|---|
| shell attacks blocked | 281 | **160** |
| benign commands scoring above zero | 74 | **0** |
| benign commands blocked | 74 | **0** |
| benign prose blocked, content path | 66 | **1** (`bp-055`, documented by ID in `tests/test_benign_prose.py`) |
| benign prose blocked, tool-argument path | 66 | **0** |

So the false-block rate to read beside 160 of 281 is **0 of 74** on commands and
**1 of 66** on prose. The one prose blocker is named rather than absorbed into a
percentage, so a second one shows up as a new entry instead of as a rounding
change. Both benign gates are asserted, and the script exits non-zero if either
is violated.

Reported by family and not per command, the same discipline the README's
[Coverage and limitations](README.md#coverage-and-limitations) section follows.
Read that section for what 160 of 281 does and does not mean.

## Methodology

* 20 warmup calls per shape, discarded, so import and regex compilation are not
  counted
* one `time.perf_counter()` pair around one sensor call
* nearest-rank percentiles over every sample. No trimming, no outlier removal
* garbage collection left on. Collections land in the numbers
* null telemetry reporter, so no emit cost is inside the numbers
* single process, single thread, no concurrency, no network

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
