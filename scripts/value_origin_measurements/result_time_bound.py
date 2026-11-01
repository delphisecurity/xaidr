"""What one tool result's reading costs when its text is long non-ASCII host names,
whose cost the work units do not track (each host is encoded label by label, for
every encoder and case reading). Wall-clock time of one ``record_tool_result``,
the worst of 3 runs per shape, at the largest documented result size (64 leaves of
64 KiB) and past it. Each reading stops at ``RESULT_TIME_BOUND_SECONDS``. Run from
the repo root of the tree under test, on each interpreter:

    PYTHONPATH=$PWD python scripts/value_origin_measurements/result_time_bound.py
"""
import contextvars
import sys
import time

from xaidr import value_origin as vo

SHARP_S = "\N{LATIN SMALL LETTER SHARP S}"


def url(i, j=0):
    """A 4,000-character URL whose host is one non-ASCII label repeated."""
    return "http://" + (SHARP_S + ".") * 1996 + f"e{i}x{j}"


def prose(i):
    """64 KiB: sixteen such URLs."""
    return " ".join(url(i, j) for j in range(16))


def hosts(i):
    """64 KiB of long non-ASCII bare host names in prose."""
    return " ".join(("ab" + SHARP_S + ".") * 120 + f"example{i}x{j}" for j in range(160))[:65_536]


SHAPES = {
    "64 x 64 KiB, 16 URLs each": lambda: [prose(i) for i in range(64)],
    "64 URLs, one a leaf": lambda: [url(i) for i in range(64)],
    "128 x 64 KiB (past the bound)": lambda: [prose(i) for i in range(128)],
    "one 4 MiB leaf": lambda: [" ".join(url(0, j) for j in range(1024))],
    "64 x 64 KiB bare hosts": lambda: [hosts(i) for i in range(64)],
}


def main():
    out = []
    for make in SHAPES.values():
        result = make()
        worst = 0.0
        for _ in range(3):
            def run():
                vo.bind_fresh_ledger()
                t = time.perf_counter()
                vo.record_tool_result("search", {"q": "x"}, result, designations=(),
                                      result_blocked=False)
                return time.perf_counter() - t
            worst = max(worst, contextvars.Context().run(run))
        out.append(f"{worst:.3f}")
    print(sys.version.split()[0], " ".join(out), "  (s, in the order:",
          "; ".join(SHAPES), ")")


if __name__ == "__main__":
    main()
