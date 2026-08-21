"""Repetition detection as a COUNTING problem, not a backtracking problem.

WHY THIS MODULE EXISTS. ``LLM04_phrase_repeat_overflow`` was written as

    (.{5,50})\\s*(?:\\1\\s*){20,}

and that pattern is a catastrophic backtracker. The capture ``.{5,50}`` gives the
engine 46 candidate unit lengths at every start offset, and inside the repeat
group ``\\1`` sits directly beside ``\\s*``. When the text is whitespace, ``\\1``
and ``\\s*`` match the SAME characters, so every repeat can be split many ways and
the splits multiply: 103 spaces matched in microseconds, 104 spaces did not finish
in 60 seconds. Measured on this tree, a 105-character input (104 spaces and one
'!') pinned a core indefinitely on the content path AND the tool-argument path.

A length cap cannot help — the trigger is structure, not size — and a watchdog
timeout must not be used either, because this scanner FAILS OPEN: an unexpected
fault returns ``allowed`` with a ``SCAN_FAILED_OPEN`` signal (sensor._emit_scan_
error). A per-scan timeout would therefore convert the hang into a CLEAN ALLOW
that an attacker triggers by appending 104 spaces to any payload — a total
detection bypass, strictly worse than the DoS.

So the pattern is replaced by what it was always trying to express. "Is there a
unit of 5-50 characters repeated at least 21 times in a row" is a question about
PERIODICITY, and periodicity is decidable in a single linear pass per period with
no backtracking surface at all, because nothing is ever re-scanned.

THE ALGORITHM, and why it is exact.

  1. Whitespace runs collapse to a single space. That is what the rule's ``\\s*``
     was expressing — repeats separated by "any run of whitespace" — and once the
     separator is uniform, "unit repeated with whitespace between" becomes plain
     periodicity. It is also what removes the ambiguity that caused the blowup:
     after collapsing, no character can be claimed by both the unit and the
     separator.

  2. For each period p in [5, 50], walk a GRID of p-sized blocks and count
     consecutive equal neighbours: ``s[j:j+p] == s[j+p:j+2p]`` for j = 0, p, 2p …
     Each comparison is one C-level memcmp; the whole pass over a period costs
     n byte-comparisons and n/p Python steps, and no position is ever revisited.

     The grid does not need to be aligned to the repetition. If a span has period
     p and holds k repeats, every pair of adjacent p-blocks lying entirely inside
     that span is equal, and a span of k*p characters contains at least k-2 such
     aligned pairs whatever the offset. So requiring ``min_repeats - 2``
     consecutive grid hits can never miss a real run — the -2 is exactly the
     alignment slack, not a fudge factor.

  3. A grid hit is then EXPANDED to the true maximal run (walk back and forward
     while ``s[i] == s[i+p]``) and the repeat count is computed exactly, so the
     slack in step 2 produces candidates, never verdicts.

Total cost is bounded by sum over p of n = 46n byte comparisons and
n * sum(1/p) ~ 2.3n interpreter steps, for ANY input — no input-dependent blowup
exists, because the work is a function of length and period alone.

The module is standard library only and has no regex with a quantifier over a
group, by construction.
"""

import re

# Whitespace-run collapse. One bounded quantifier over a single character class,
# no group, no adjacent quantifier — the one shape that cannot backtrack.
_WS_RUN = re.compile(r"\s+")

# Defaults mirror the retired pattern exactly: a unit of 5-50 characters, and
# `\1` once plus `{20,}` more = 21 occurrences.
MIN_UNIT = 5
MAX_UNIT = 50
MIN_REPEATS = 21


def _candidate_periods(s: str, min_unit: int, max_unit: int, min_repeats: int):
    """Cheap linear PRE-FILTER: could this text contain any qualifying run?

    A qualifying run is a span of at least ``min_unit * min_repeats`` characters
    with some period p <= ``max_unit``. Probe positions every ``max_unit``
    characters and ask, with one C-level ``str.find``, whether the ``min_unit``
    characters at the probe recur within the next ``max_unit`` characters.

    IT CANNOT MISS A RUN, and the arithmetic is the whole argument. Let a run
    start at ``a`` with length ``L >= min_unit * min_repeats`` and period
    ``p <= max_unit``. Probes sit on multiples of ``max_unit``, so the first probe
    ``k`` at or after ``a`` satisfies ``k < a + max_unit``. The recurrence this
    probe looks for ends at ``k + p + min_unit < a + 2*max_unit + min_unit``, and
    the guard below only enables the pre-filter when
    ``min_unit * min_repeats >= 2*max_unit + min_unit`` — i.e. when that endpoint
    is still inside the run. Both probe and its recurrence therefore lie within
    the periodic span, so the characters agree and ``find`` succeeds.

    With the shipped parameters the condition is 105 >= 105: exact, not
    approximate. If a caller passes parameters that break it, the pre-filter
    disables itself rather than silently narrowing detection.

    Returns ``None`` when no probe found any recurrence (no run can exist), else
    the SET OF DISTANCES at which recurrences were seen. Those distances are the
    periods the text actually exhibits, so the caller tries them first; it still
    sweeps every period afterwards, so the set is an ordering hint and never a
    restriction on what can be detected.
    """
    if min_unit * min_repeats < 2 * max_unit + min_unit:
        return set()  # guarantee does not hold here — sweep everything, no hint
    n = len(s)
    k = 0
    window = max_unit + min_unit
    found = set()
    while k + min_unit <= n:
        q = s.find(s[k:k + min_unit], k + 1, k + window)
        if q != -1:
            found.add(q - k)
        k += max_unit
    return found or None


def _expand(s: str, p: int, lo: int, hi: int) -> tuple:
    """Maximal run of period ``p`` covering the grid hit [lo, hi).

    Returns ``(start, end)`` such that ``s[i] == s[i + p]`` for every i in
    [start, end). Walks outward only, so each character is visited once per
    candidate and the cost is proportional to the run it reports.
    """
    start = lo
    while start > 0 and s[start - 1] == s[start - 1 + p]:
        start -= 1
    end = hi
    n = len(s)
    while end + p < n and s[end] == s[end + p]:
        end += 1
    return start, end


def find_phrase_repeat(
    text: str,
    min_unit: int = MIN_UNIT,
    max_unit: int = MAX_UNIT,
    min_repeats: int = MIN_REPEATS,
    collapse_whitespace: bool = True,
    allow_newline_in_unit: bool = True,
):
    """Return the repeated span when ``text`` repeats a ``min_unit``-``max_unit``
    character unit at least ``min_repeats`` times in a row, else ``None``.

    ``collapse_whitespace`` reproduces the retired pattern's ``\\s*`` BETWEEN
    repeats and must match the rule being replaced. It is True for
    ``LLM04_phrase_repeat_overflow`` — whose ``(?:\\1\\s*){20,}`` allowed a
    whitespace run before every repeat — and False for ``LLM04_phrase_repeat``,
    whose ``\\1{15,}`` allowed none, so that rule keeps requiring the copies to be
    contiguous. Getting this backwards silently changes what each rule detects,
    which is why it is a parameter and not a constant.

    ``allow_newline_in_unit`` reproduces the other half of the retired patterns'
    semantics, and it is not cosmetic. Python's ``.`` does not match a newline
    without DOTALL, so ``(.{10,1000})\\1{4,}`` could never see a repeated unit
    that spanned a line break. Ignoring that made the replacement fire on 729 of
    4000 randomised inputs the regex rejected — repeated LINES, which is what a
    CSV, a log file or a JSON array looks like. Setting this False confines the
    search to one line at a time and restores the original behaviour exactly.
    ``LLM04_phrase_repeat_overflow`` keeps it True on purpose: its ``\\s*`` sat
    between the repeats and absorbed newlines, so for that rule crossing a line
    break was always allowed.

    Linear in the input for every input. Never raises on odd input; a non-string
    or an empty string is simply not a repetition.
    """
    if not text or not isinstance(text, str):
        return None

    if not allow_newline_in_unit and "\n" in text:
        # Same total work: the segments partition the input.
        for segment in text.split("\n"):
            hit = _find_in(segment, min_unit, max_unit, min_repeats,
                           collapse_whitespace)
            if hit:
                return hit
        return None
    return _find_in(text, min_unit, max_unit, min_repeats, collapse_whitespace)


def _find_in(text, min_unit, max_unit, min_repeats, collapse_whitespace):
    """The period search over one span that the caller has already decided is a
    single searchable unit (the whole text, or one line of it)."""
    s = _WS_RUN.sub(" ", text).strip() if collapse_whitespace else text
    n = len(s)
    if n < min_unit * min_repeats:
        return None
    hints = _candidate_periods(s, min_unit, max_unit, min_repeats)
    if hints is None:
        return None

    # A run of k repeats gives at least k-2 consecutive aligned grid hits,
    # whatever the offset of the run relative to the grid (see module docstring).
    need_hits = max(1, min_repeats - 2)

    # Periods the pre-filter actually observed go first — a matching input then
    # returns on its own period instead of paying for every shorter one. The full
    # sweep still follows, so this changes cost and not the answer.
    hinted = [p for p in sorted(hints) if min_unit <= p <= max_unit]
    order = hinted + [p for p in range(min_unit, max_unit + 1) if p not in hints]

    for p in order:
        if p * min_repeats > n:
            # No room for this period. `continue`, not `break`: the sweep is no
            # longer in ascending order once the hinted periods go first.
            continue
        run = 0
        hit_start = 0
        limit = n - 2 * p
        j = 0
        while j <= limit:
            if s[j:j + p] == s[j + p:j + 2 * p]:
                if run == 0:
                    hit_start = j
                run += 1
                if run >= need_hits:
                    start, end = _expand(s, p, hit_start, j + p)
                    # end - start is the length of the AGREEMENT region; the full
                    # repeated span is that plus one more unit.
                    total = end - start + p
                    if total // p >= min_repeats:
                        return s[start:start + total]
                    run = 0  # not enough repeats here; keep scanning this period
            else:
                run = 0
            j += p
    return None
