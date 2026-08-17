#!/usr/bin/env python3
"""Measure sensor latency at every boundary and print one table.

Run it from the repository root:

    python scripts/benchmark.py

What it is for: the published latency figures are useless without the machine
they came from, the payload size they describe, and whether they are a median
or a tail. This script prints all three, on YOUR hardware, so the number in
BENCHMARKS.md is something you can check rather than something you have to
trust.

WHAT THIS SCRIPT IS NOT: it asserts nothing and gates nothing. There is no
latency budget in here, no floor, no "must be under N ms". It prints. Exit
status is 0 unless the run itself failed, because a slow machine is a fact
about the machine, not a regression. The gates that hold the line live in the
test suite; the false-positive gate lives in scripts/corpus_report.py.

Standard library and the `xaidr` package only, same as corpus_report.py: no
third-party imports, no network, no telemetry (the sensor is constructed with a
null reporter).

Methodology, stated rather than implied:

  * every shape is warmed up WARMUP times before anything is timed, so import,
    regex compilation and first-call caching are not in the numbers
  * every timed call is a single `time.perf_counter()` pair around one sensor
    call, with the sensor's own stdout swallowed
  * nothing is discarded. No trimming, no outlier removal, no gc disabling.
    Percentiles are nearest-rank over every sample taken
  * the size sweep is ONE pass per cell, and the sample count is printed beside
    every row so you can see how much a p99 is worth at that size
  * the headline mix is run THREE times end to end and all three are printed.
    The headline figure is the best of the three medians, labelled as such

The sample counts fall as the payload grows, because a 256 KB scan costs about
a thousand times what a 200 B scan costs and a fixed count would make the run
take an hour. That is a deliberate trade and it is why n is in the table.
"""
from __future__ import annotations

import io
import math
import os
import platform
import statistics
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_DIR = os.path.join(REPO_ROOT, "scripts")

# Measure THIS working tree, not whatever `xaidr` happens to be installed. Same
# reasoning as corpus_report.py, and the same failure if it is skipped: the
# table would silently describe a package you are not editing. SCRIPT_DIR is
# added too so the provenance helper below imports under `python -m` as well as
# under `python scripts/benchmark.py`.
sys.path.insert(0, REPO_ROOT)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# One provenance helper, not two. corpus_report.py already answers "which xaidr
# produced this table and is it the repo copy", and a second implementation
# would be a second thing to keep true.
from corpus_report import _package_provenance  # noqa: E402

WIDTH = 78

WARMUP = 20            # discarded calls per shape, before any timing
MIX_ITERATIONS = 100   # passes over the traffic mix, per repeat
MIX_REPEATS = 3        # full repeats of the mix, all printed

# Payload sizes for the sweep, in bytes, with the sample count for each. The
# counts fall as the size rises; see the methodology note in the docstring.
SIZE_PLAN = [
    (200,     "200 B",  200),
    (1_024,   "1 KB",   200),
    (4_096,   "4 KB",   100),
    (16_384,  "16 KB",   40),
    (65_536,  "64 KB",   15),
    (262_144, "256 KB",   7),
]

# Filler that reads like agent traffic rather than like `'x' * n`, which no regex
# engine treats the way it treats real text. Because the sweep REPEATS this block
# to reach each size, the distinct-word count saturates almost immediately while
# the byte count keeps rising. That is deliberate: it holds vocabulary roughly
# fixed so the sweep isolates length, and it is why the sweep must not be read as
# a general size-to-latency curve for arbitrary text.
FILLER = (
    "The deploy to us-east-1 finished at 14:02 UTC and every replica returned "
    "200 on the health check. Queue depth peaked at 1,840 and drained inside "
    "four minutes. One worker restarted after an OOM at 13:58; the pod came "
    "back clean and no requests were dropped. Follow-up is tracked in "
    "PLAT-4471. Nothing else in the window needs attention. "
)


# -- helpers -----------------------------------------------------------------

class _Devnull(io.TextIOBase):
    """Swallow the sensor's own detection prints without buffering them.

    A StringIO would work but grows without bound across ~10,000 timed calls,
    and allocating one per call would land inside the measurement.
    """

    def write(self, s):  # noqa: D102
        return len(s)

    def flush(self):  # noqa: D102
        pass


def _payload(nbytes: int) -> str:
    """Ordinary-looking text of exactly `nbytes` ASCII bytes."""
    reps = (nbytes // len(FILLER)) + 2
    return (FILLER * reps)[:nbytes]


def _percentile(sorted_samples, q: float) -> float:
    """Nearest-rank percentile. Plain and stated, so the numbers are checkable."""
    if not sorted_samples:
        return float("nan")
    k = math.ceil(q * len(sorted_samples)) - 1
    return sorted_samples[max(0, min(k, len(sorted_samples) - 1))]


def _stats(samples_ms):
    """median / p95 / p99 / max / n for a list of millisecond timings."""
    ordered = sorted(samples_ms)
    return {
        "median": statistics.median(ordered) if ordered else float("nan"),
        "p95": _percentile(ordered, 0.95),
        "p99": _percentile(ordered, 0.99),
        "max": ordered[-1] if ordered else float("nan"),
        "n": len(ordered),
    }


def _ms(value: float) -> str:
    if value != value:  # NaN
        return "     -"
    if value >= 100:
        return f"{value:>7.0f}"
    if value >= 10:
        return f"{value:>7.1f}"
    return f"{value:>7.2f}"


def _rule(char: str = "─") -> str:
    return char * WIDTH


def _progress(message: str) -> None:
    """Progress goes to stderr so the table on stdout stays pipeable."""
    print(message, file=sys.stderr, flush=True)


def _time_call(fn, *args, **kwargs) -> float:
    """One call, milliseconds. The redirect is set up by the caller, not here."""
    start = time.perf_counter()
    fn(*args, **kwargs)
    return (time.perf_counter() - start) * 1000.0


# -- what gets measured ------------------------------------------------------

def _boundaries(sensor):
    """The four public scan boundaries, and the exact call made for each.

    The call shape is printed with the table. A latency number for
    "scan_tool_call" means nothing unless you know what was in the arguments.
    """
    return [
        ("scan input",
         'scan(text, direction="input")',
         lambda text: sensor.scan(text, direction="input")),
        ("scan_output",
         "scan_output(text)",
         lambda text: sensor.scan_output(text)),
        ("scan_tool_call",
         'scan_tool_call("send_message", {"body": text})',
         lambda text: sensor.scan_tool_call("send_message", {"body": text})),
        ("scan_a2a",
         'scan_a2a(text, destination="peer-agent")',
         lambda text: sensor.scan_a2a(text, destination="peer-agent")),
    ]


def _traffic_mix(sensor):
    """Ordinary agent traffic, printed in full with the results.

    Seven shapes: short user prompts, tool calls with short arguments, a brief
    model answer, a small delegation envelope. Deliberately weighted to small
    messages, because that is what agent traffic is. One entry is attack-shaped
    on purpose, so the detecting path is represented rather than only the clean
    one.

    What is deliberately NOT here: retrieved documents, RAG chunks, pasted logs.
    Those cost more (see the size sweep, and the note under it), and putting one
    in a seven-item mix would let a single shape decide the reported tail. They
    are a real workload, but they are a DIFFERENT workload, and averaging the
    two produces a number that describes neither.
    """
    prompt_short = "What is the status of the us-east-1 deploy?"
    answer_plain = (
        "The us-east-1 deploy completed at 14:02 UTC. All twelve replicas are "
        "healthy and the error rate is flat at 0.02%."
    )
    a2a_plain = (
        "Please review the open pull requests on the payments service."
    )

    return [
        ("scan_tool_call", "read_file, short path", "README.md",
         lambda: sensor.scan_tool_call("read_file", {"path": "README.md"})),
        ("scan_tool_call", "run_command, benign", "git status --short",
         lambda: sensor.scan_tool_call("run_command", {"command": "git status --short"})),
        ("scan_tool_call", "run_command, destructive", "rm -rf /var/lib/data",
         lambda: sensor.scan_tool_call("run_command", {"command": "rm -rf /var/lib/data"})),
        ("scan input", "short user prompt", prompt_short,
         lambda: sensor.scan(prompt_short, direction="input")),
        ("scan_tool_call", "run_sql, bounded delete",
         "DELETE FROM sessions WHERE expires_at < now()",
         lambda: sensor.scan_tool_call(
             "run_sql", {"query": "DELETE FROM sessions WHERE expires_at < now()"})),
        ("scan_a2a", "small delegation envelope", a2a_plain,
         lambda: sensor.scan_a2a(a2a_plain, destination="reviewer-agent")),
        ("scan_output", "brief model answer", answer_plain,
         lambda: sensor.scan_output(answer_plain)),
    ]


# -- measurement -------------------------------------------------------------

def measure_sizes(sensor):
    """Latency per boundary per payload size. Returns {boundary: {size: stats}}."""
    results = {}
    for name, shape, call in _boundaries(sensor):
        per_size = {}
        for nbytes, label, count in SIZE_PLAN:
            text = _payload(nbytes)
            for _ in range(min(WARMUP, max(2, count // 4))):
                call(text)
            samples = [_time_call(call, text) for _ in range(count)]
            per_size[label] = _stats(samples)
            _progress(f"  {name:<16} {label:>7}  n={count:<4} "
                      f"median {per_size[label]['median']:.2f} ms")
        results[name] = {"shape": shape, "sizes": per_size}
    return results


def measure_mix(sensor):
    """The headline mix, repeated end to end. Returns (repeats, per_boundary).

    `repeats` is one stats dict per full repeat, over every timed call in it.
    `per_boundary` and `per_item` split the LAST repeat by boundary and by
    individual shape, so the four boundaries are comparable on identical traffic
    and the reader can see WHICH shape owns the tail rather than guessing.
    """
    mix = _traffic_mix(sensor)
    for _, _, _, call in mix:
        for _ in range(WARMUP):
            call()

    repeats = []
    per_boundary = {}
    per_item = {}
    for repeat in range(MIX_REPEATS):
        all_samples = []
        by_boundary = {}
        by_item = {}
        for _ in range(MIX_ITERATIONS):
            for boundary, label, _payload_text, call in mix:
                elapsed = _time_call(call)
                all_samples.append(elapsed)
                by_boundary.setdefault(boundary, []).append(elapsed)
                by_item.setdefault(label, []).append(elapsed)
        repeats.append(_stats(all_samples))
        per_boundary = {k: _stats(v) for k, v in by_boundary.items()}
        per_item = {k: _stats(v) for k, v in by_item.items()}
        _progress(f"  mix repeat {repeat + 1}/{MIX_REPEATS}  n={repeats[-1]['n']}  "
                  f"median {repeats[-1]['median']:.2f} ms")
    return mix, repeats, per_boundary, per_item


# -- report ------------------------------------------------------------------

def _print_header(cap_chars, cap_windows, cap_budget):
    pkg_path, pkg_version, pkg_is_repo = _package_provenance()
    impl = platform.python_implementation()

    print(_rule("="))
    print("xaidr latency benchmark")
    print(_rule("="))
    print(f"platform : {platform.platform()}")
    print(f"machine  : {platform.machine()}")
    print(f"processor: {platform.processor() or 'unknown'}")
    print(f"cpu count: {os.cpu_count()}")
    print(f"python   : {impl} {platform.python_version()}")
    print(f"package  : {pkg_path}")
    print(f"version  : {pkg_version}")
    if not pkg_is_repo:
        print(f"WARNING: that package is NOT this repository ({REPO_ROOT}).")
        print("         The numbers below describe the installed copy, not your changes.")
    print(_rule("="))
    print()
    print("METHODOLOGY")
    print(_rule())
    print(f"  warmup            : {WARMUP} discarded calls per shape")
    print("  timing            : one perf_counter pair per sensor call")
    print("  percentiles       : nearest-rank over every sample, nothing trimmed")
    print("  gc                : left on. Collections land in the numbers")
    print("  size sweep        : one pass per cell, n printed per row")
    print(f"  headline mix      : {MIX_REPEATS} full repeats, all printed, "
          f"{MIX_ITERATIONS} passes each")
    print("  concurrency       : none. Single process, single thread, no network")
    print("  telemetry         : null reporter. No emit cost in the numbers")
    print()
    print("  A p99 over 7 samples is the 7th of 7. Read n before reading the tail.")
    print()
    print("INTERNAL INPUT CAP")
    print(_rule())
    print(f"  L1_MAX_SCAN_CHARS   : {cap_chars:,} chars (~{cap_chars / 1024:.0f} KB)")
    print(f"  MAX_SCAN_WINDOWS    : {cap_windows}")
    print(f"  TOTAL_SCAN_BUDGET   : {cap_budget:.1f} s")
    print()
    print("  The sweep below holds vocabulary roughly constant and varies length,")
    print("  so it isolates the regex work, which does grow with byte count up to")
    print("  the cap. Past the cap the input is scanned in overlapping windows")
    print("  under a fixed total budget, so the curve flattens and then stops")
    print("  growing. A 256 KB row that is not four times the 64 KB row is the cap")
    print("  working, not an error in the measurement.")
    print()


def _print_size_tables(size_results, cap_chars):
    print(_rule("="))
    print("LATENCY BY BOUNDARY AND PAYLOAD SIZE   (milliseconds)")
    print(_rule("="))
    for name in ("scan input", "scan_output", "scan_tool_call", "scan_a2a"):
        block = size_results[name]
        print()
        print(f"{name}   {block['shape']}")
        print(f"{'payload':<10}{'median':>9}{'p95':>9}{'p99':>9}{'max':>9}{'n':>7}   note")
        print(_rule())
        for nbytes, label, _count in SIZE_PLAN:
            row = block["sizes"][label]
            note = "past the cap" if nbytes > cap_chars else ""
            print(f"{label:<10}{_ms(row['median']):>9}{_ms(row['p95']):>9}"
                  f"{_ms(row['p99']):>9}{_ms(row['max']):>9}{row['n']:>7}   {note}")
    print()


def _print_mix(mix, repeats, per_boundary, per_item):
    print(_rule("="))
    print("HEADLINE: ORDINARY AGENT TRAFFIC   (milliseconds)")
    print(_rule("="))
    print()
    print("What is in the mix, one timed call each per pass:")
    for boundary, label, payload_text, _call in mix:
        size = len(payload_text.encode("utf-8"))
        print(f"  {boundary:<16} {label:<28} {size:>6} B")
    print()
    print("  Deliberately weighted to small messages, because that is what agent")
    print("  traffic is. One of the seven is attack-shaped, so the detecting path")
    print("  is represented rather than only the clean one. Retrieved documents")
    print("  and pasted logs are NOT here: they cost more, and one of them in a")
    print("  seven-item mix would decide the reported tail on its own. See the")
    print("  size sweep above for what larger input costs.")
    print()

    print(f"{'repeat':<10}{'median':>9}{'p95':>9}{'p99':>9}{'max':>9}{'n':>7}")
    print(_rule())
    for index, row in enumerate(repeats, start=1):
        print(f"{'#' + str(index):<10}{_ms(row['median']):>9}{_ms(row['p95']):>9}"
              f"{_ms(row['p99']):>9}{_ms(row['max']):>9}{row['n']:>7}")
    print(_rule())
    best = min(repeats, key=lambda r: r["median"])
    print(f"{'best of ' + str(len(repeats)):<10}{_ms(best['median']):>9}"
          f"{_ms(best['p95']):>9}{_ms(best['p99']):>9}{_ms(best['max']):>9}"
          f"{best['n']:>7}")
    print()
    print("  All repeats are printed. The headline is the best median of them,")
    print("  which is the friendliest honest reading; the spread between the")
    print("  repeats is the run-to-run noise on this machine.")
    print()

    print("Same mix, split by boundary (last repeat):")
    print(f"{'boundary':<18}{'median':>9}{'p95':>9}{'p99':>9}{'max':>9}{'n':>7}")
    print(_rule())
    for name in ("scan input", "scan_output", "scan_tool_call", "scan_a2a"):
        row = per_boundary.get(name)
        if not row:
            continue
        print(f"{name:<18}{_ms(row['median']):>9}{_ms(row['p95']):>9}"
              f"{_ms(row['p99']):>9}{_ms(row['max']):>9}{row['n']:>7}")
    print()

    print("Same mix, per shape (last repeat). This is where the tail comes from:")
    print(f"{'shape':<38}{'median':>9}{'p95':>9}{'max':>9}{'n':>7}")
    print(_rule())
    for _boundary, label, _payload_text, _call in mix:
        row = per_item.get(label)
        if not row:
            continue
        print(f"{label:<38}{_ms(row['median']):>9}{_ms(row['p95']):>9}"
              f"{_ms(row['max']):>9}{row['n']:>7}")
    print()
    print("  Cost tracks how much text arrives, not whether a rule fires: the")
    print("  regex layer dominates and scales with byte count. Distinct vocabulary")
    print("  adds a smaller second term, because the typo normalizer runs an edit-")
    print("  distance match per unique token, so a varied paragraph costs somewhat")
    print("  more than a repetitive one of the same length. Not a verdict table.")
    print()


def _print_footer():
    print(_rule("="))
    print("These are numbers from ONE machine. Run this on yours before you put")
    print("the sensor on a latency-sensitive path. For the false-positive side,")
    print("which is the other half of any detection claim, run:")
    print("    python scripts/corpus_report.py")
    print(_rule("="))


def main() -> int:
    try:
        from xaidr import Sensor
    except ImportError as exc:
        print(f"error: the xaidr package is not importable: {exc}", file=sys.stderr)
        print("       install it first: pip install .", file=sys.stderr)
        return 2

    try:
        from xaidr.scanner.l1 import (
            L1_MAX_SCAN_CHARS as cap_chars,
            MAX_SCAN_WINDOWS as cap_windows,
            TOTAL_SCAN_BUDGET_SEC as cap_budget,
        )
    except ImportError:  # pragma: no cover - the constants have been stable
        cap_chars, cap_windows, cap_budget = 100_000, 8, 1.0

    class _NullReporter:
        """No telemetry, no network. Emitting would measure the reporter too."""

        def report(self, batch): pass

        def close(self): pass

    sensor = Sensor(agent_id="benchmark", enforcement_mode="monitor",
                    reporter=_NullReporter())

    _progress("measuring (a few minutes; the 256 KB rows are the slow part)")
    import contextlib
    try:
        with contextlib.redirect_stdout(_Devnull()):
            size_results = measure_sizes(sensor)
            mix, repeats, per_boundary, per_item = measure_mix(sensor)
    finally:
        # close_sync, not close: close() is a coroutine and calling it from
        # sync code silently drops it (and warns).
        with contextlib.suppress(Exception):
            sensor.close_sync()

    _print_header(cap_chars, cap_windows, cap_budget)
    _print_size_tables(size_results, cap_chars)
    _print_mix(mix, repeats, per_boundary, per_item)
    _print_footer()
    return 0


if __name__ == "__main__":
    sys.exit(main())
