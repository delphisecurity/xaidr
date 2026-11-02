# Performance and resilience

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

In-process, single core, no network call in the scan path. Seven shapes of
ordinary agent traffic, 700 timed calls per repeat, three repeats:

| | measured | budget |
|---|---:|---:|
| Median scan | **0.43 ms** | — |
| p95 | **0.57 ms** | — |
| p99 | **0.62 ms** | **3 ms** |

The 3 ms p99 is a **ceiling**, about five times the measured p99. It is the
number to design against; the measured column is what one machine actually did,
not a promise about yours. The three repeats agree to within 0.01 ms at the
median and 0.03 ms at p95, and [BENCHMARKS.md](https://github.com/delphisecurity/xaidr/blob/main/BENCHMARKS.md) carries all three, the machine
they ran on, and the per-shape breakdown. Latency scales with input size and is
bounded by a hard input ceiling and a fixed window count (a long input is read in
at most two windows), with wall-clock backstops behind them, so a pathologically
large input cannot hang your agent, and what is read never depends on how busy
the machine is. Measure on your own traffic before enabling
hard blocking on a latency-sensitive path.

**Know the magnitude before you put this on an untrusted path.** Those
sub-millisecond figures describe agent-sized messages. A very large prompt is
bounded but not fast: cost is dominated by the regex layer and scales with byte
count up to the internal ceiling, then flattens. 200 B of prose scans in about
2.3 ms on the input path, and 256 KB in about **1.4 s**; larger inputs take about
the same, because the cap has already been reached. Nothing is unbounded and
nothing hangs, but if callers can hand you arbitrarily large text, either cap the
input yourself before scanning or scan off the request path.

**The worst case per path, on the CI runners.** What a scan or a reading
examines is decided by work (every L1 rule over at most 100 000 characters, a
long input in at most two windows, a tool result's reading by its work meter),
so the same input reads the same on every machine. What that work costs in time
is the figure below: the worst CPU time of one call on each path's adversarial
inputs (`scripts/scan_paths.py`), the worst of every pytest cell of GitHub's
`ubuntu-latest` runners (CI run 41462272430, 2026-11-02; the slowest is py3.10
on every path). The runners are the reference because they are the slowest
machine measured: the build machine (macOS arm64, 3.12.15) takes about a third
as long. Each path keeps one timing check (`tests/test_path_timing.py`) at 1.5
times its runner figure, or 50 ms where the figure is too small for a shared
runner to tell from its own noise. Every CI pytest cell prints these figures
again (`python scripts/scan_paths.py`).

| path | worst input | runners | check | build machine |
|---|---|---:|---:|---:|
| input scan, one `scan()` | 1 MB of `a@b.com ` | 5.368 s | 8.052 s | 1.586 s |
| output scan, one `scan_output()` | 1 MB of `a@b.com ` | 1.710 s | 2.566 s | 0.520 s |
| tool-call scan, one argument | `curl ` x 2000 | 0.421 s | 0.632 s | 0.142 s |
| one L1 rule on one input, at the cap | `curl ` x 20 000 (the battery's verb flood) | 0.548 s | 0.822 s | 0.152 s |
| the typo normalizer | `a.` x 200 000 | 0.145 s | 0.217 s | 0.043 s |
| a text detector | a URL of 200 000 `%2F` | 0.328 s | 0.492 s | 0.095 s |
| the command and SQL parsers | a command at the input cap | 0.033 s | 0.05 s | 0.009 s |
| the A2A id check | `..%2f` x 16 000 | 0.002 s | 0.05 s | 0.001 s |
| one tool result's reading | 64 x 64 KiB of non-ASCII host names | 5.256 s | 7.884 s | 1.164 s |

The wall-clock limits behind the work are backstops, 120 s, and when one fires
the verdict carries its own reason. With the clock run ten times fast, which is
what a machine ten times slower than a runner looks like to them, the runners'
worst case reached 43.7 s of the 120 s (a document over the cap, py3.10), and no
backstop fired in any cell.

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

Verified with `python -m pytest -q` in the `base` configuration — `pip install .`
plus `pytest`, no extras and no framework installed. That is the configuration
quoted because it is the one that proves the zero-dependency claim, and it runs
on every pull request as CI's `pytest (py<ver>, base)` job.

**No pass count is published here.** This paragraph previously stated
`7603 passed, 163 skipped`; that figure is superseded and withdrawn, as recorded in the retraction record of <!-- suite-count-ok: superseded figure, quoted so a reader who met it sees it marked superseded -->
[docs/testing.md](https://github.com/delphisecurity/xaidr/blob/main/docs/testing.md).
A hand-kept count drifts stale with every release, for the reasons given there.
The current count is printed in the log of every CI run by the job that measured
it; the argument for reading it there rather than here is in that document. What
matters for this page is the pass/fail, not the total: a red `base` job means
the zero-dependency claim is broken, and no literal in a markdown file can tell
you that.

Configurations, what CI does and does not build, and the `base` skip breakdown
are also in
[docs/testing.md](https://github.com/delphisecurity/xaidr/blob/main/docs/testing.md).
It is a **source** claim either way, not an install claim: the wheel ships the
`xaidr` package only. The sdist carries `tests/`, so verifying
it means an extracted sdist or a clone of the repository.
