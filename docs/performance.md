# Performance and resilience

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

In-process, single core, no network call in the scan path. Seven shapes of
ordinary agent traffic, 700 timed calls per repeat, three repeats:

| | measured | budget |
|---|---:|---:|
| Median scan | **0.43 ms** | — |
| p95 | **0.57 ms** | — |
| p99 | **0.63 ms** | **3 ms** |

The 3 ms p99 is a **ceiling**, about five times the measured p99. It is the
number to design against; the measured column is what one machine actually did,
not a promise about yours. The three repeats agree to within 0.03 ms at every
percentile, and [BENCHMARKS.md](https://github.com/delphisecurity/xaidr/blob/main/BENCHMARKS.md) carries all three, the machine
they ran on, and the per-shape breakdown. Latency scales with input size and is
bounded by a hard input ceiling and a wall-clock budget, so a pathologically
large input cannot hang your agent. Measure on your own traffic before enabling
hard blocking on a latency-sensitive path.

**Know the magnitude before you put this on an untrusted path.** Those
sub-millisecond figures describe agent-sized messages. A very large prompt is
bounded but not fast: cost is dominated by the regex layer and scales with byte
count up to the internal ceiling, then flattens. 200 B of prose scans in about
2.3 ms on the input path, and 256 KB in about **1.4 s**; larger inputs take about
the same, because the cap has already been reached. Nothing is unbounded and
nothing hangs, but if callers can hand you arbitrarily large text, either cap the
input yourself before scanning or scan off the request path.

**Reproduce this yourself: `python scripts/benchmark.py`.** It prints the
machine, the payload size, and median/p95/p99/max per boundary, and it asserts
nothing.

**Resilience properties, all exercised by the test suite:**

- **Fails open, never crashes the host.** An unexpected internal fault emits a
  degraded signal and returns `allowed` rather than propagating. The tradeoff is
  explicit: during a sensor fault, traffic passes unscanned — availability over
  blocking — and `degraded=true` is the compensating signal you alert on.
- **Never hangs.** Bounded input ceiling, bounded time budget.
- **Survives adversarial structure.** Deeply nested JSON, as input or as an A2A
  envelope, returns a verdict rather than crashing.
- **Malformed content is safe.** Badly formed input cannot turn the sensor into
  a denial-of-service risk.

Verified with `python -m pytest -q`. The headline figure is the `base`
configuration — `pip install .` plus `pytest`, no extras and no framework
installed: **7436 passed, 144 skipped, 0 failed**, identical across three
consecutive serial runs. That is the configuration quoted because it is the one
that proves the zero-dependency claim.

**The other configurations, their pass counts and the skip breakdown are in
[docs/testing.md](https://github.com/delphisecurity/xaidr/blob/main/docs/testing.md).**
A pass count means nothing without the configuration that produced it, because
whole test classes only exist when a framework is importable, so all of them are
given there rather than the flattering one. It is a **source-tree** claim: the
wheel and the sdist ship the `xaidr` package only, with no `tests/` directory, so
verifying it means cloning the repository.
