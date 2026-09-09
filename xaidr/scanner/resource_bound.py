"""Structural detection of REMOVED BOUNDS in tool arguments (ASI04 / LLM04 —
resource exhaustion, denial-of-wallet, unbounded fan-out).

WHAT THE SIGNAL IS, AND WHAT IT IS NOT. It is NOT magnitude. Read against the
190-call production benign corpus, every high-volume benign call names a finite
extent and carries its bound as a NUMBER:

    run_payroll(employees_estimate=5200, approval="PAY-9921")
    batch_infer(items_estimate=2100000, batch_size=5000)
    backfill(partitions_estimate=10000, parallelism=8)
    batch_fetch(count_estimate=500, rate_limit_per_sec=2)
    write_to_s3(rows=1200000)                 retention_hours=168, ttl_days=90

and every ASI04 attack argument declares that a bound is ABSENT:

    scale_workers(count=5000, budget_cap="none")
    provision_infra(instances="unlimited", spend_limit="off")
    schedule_job(concurrency="unbounded")
    batch_infer(max_cost="unset")

2.1 million rows is routine; ``spend_limit="off"`` is not. So this detector never
reads a quantity. It reads whether the caller SAID there is no ceiling.

WHY THAT MATTERS FOR DEFAULT-ON. A threshold ("more than N workers") is
deployment-relative — N is reckless for one deployer and a Tuesday for the next —
which is the argument that correctly keeps ``delegation_rate_threshold`` off by
default. This carries no threshold. ``count=5000`` is invisible here;
``budget_cap="none"`` is not, and there is no deployment in which the caller who
named a budget cap meant to remove it. That is what makes this a detector rather
than deployer configuration. The part of ASI04 that genuinely IS deployer
configuration — "5000 workers is 100x normal FOR US" — is deliberately NOT built:
it needs a per-deployment baseline this sensor does not have, and it belongs to
the policy engine and the (opt-in) circuit breaker.

WHY THIS IS NOT SECRETLY A LIST. It keys on no tool name, no model name, and no
number. Two lexical classes decide it:

  * the VALUE must be a NULLIFIER — one of the English words whose meaning is
    "no ceiling" (unlimited, unbounded, infinite, forever, never, none, off,
    unset). This is a closed function-word class, not an open enumeration of
    instances: the reason G2 stopped on crypto-mining is that miner image names
    are an open set of proper nouns with no generative rule, and these are the
    opposite of that.
  * the KEY must carry a BOUND morpheme (limit, cap, max, quota, budget, cost,
    spend, ttl, retention, timeout, deadline, threshold, concurrency, rate) or an
    EXTENT morpheme (count, instances, replicas, workers, copies, iterations,
    retries, rows). Matched on the key's COMPONENTS after splitting on
    ``_ - . space`` and camelCase — so ``strategy`` is not a "rate" key and
    ``MAX_CART_ITEMS`` is a bound key whose bound is 50.

The benign side needs no enumeration. An argument whose bounds are numbers is
silent whatever the tool is, so the payroll run, the 2.1M-row scoring job and the
10 000-partition backfill produce nothing without being named anywhere.

WHAT IS DELIBERATELY EXCLUDED, AND WHY.

  * NUMERIC SENTINELS (0, -1). ``max_retries=0`` means "do not retry" (MORE
    bounded); ``limit=0`` means "unlimited" in some APIs; ``min_replicas=0`` is a
    legitimate scale-to-zero floor. Reading them correctly requires knowing which
    tool it is — i.e. a tool list. So they are not read. Stated, not folded in.
  * BOOLEANS, in either polarity and spelled either way (``False``, ``"false"``,
    ``"no"``). Identical argument to the sentinels: ``rate_limit=false`` removes
    a ceiling, ``limit_reached=false`` says the ceiling HELD, and
    ``concurrent=false`` is the bounded direction outright. Same word, opposite
    readings, separable only by knowing the tool.
  * A DURATION, AGE OR ALERT LEVEL LEFT UNSET (``ttl="none"``,
    ``deadline="none"``, ``threshold="none"``). Nulling one of these consumes
    nothing — no spend, no fan-out — and "optional field the caller left unset"
    is the commonest shape in production arguments. These keys take only a
    STRONG nullifier, the same escalation the EXTENT class gets.
  * A BOUND NOUN QUALIFIED INTO A LABEL (``cost_center``, ``budget_code``,
    ``limit_type``). An accounting dimension is not a ceiling, and
    ``cost_center="none"`` means the expense is not yet allocated.
  * AN ABSENT ARGUMENT. Only a bound the caller explicitly nulled is read, never
    one that was never supplied, and JSON ``null`` counts as absent rather than as
    "off" because in most SDKs it selects the default. A tool that defaults to
    unlimited when its cap argument is omitted is a tool-contract problem; an
    argument dict cannot show it.
  * PROSE. A value of more than four words is content being written, not a slot
    the caller filled — the 190-call corpus contains a research KB glossary whose
    body reads "Denial of wallet: driving unbounded paid consumption" (RES-029),
    and a detector that flags the security team writing down the definition of the
    attack is the whole reason that corpus exists.
  * A BOUND NULLED INSIDE AN OPAQUE CONFIG BLOB (``config="rate_limit=none"``).
    scanner.privilege_action reads that shape for control flags, but it cannot be
    read here without matching a bound morpheme as a SUBSTRING of arbitrary text,
    which makes ``generate:`` a "rate" key. Named as a residual rather than
    shipped with that behaviour.

THE RESIDUAL THIS DETECTOR CANNOT SEPARATE, stated because it is measured and
not hypothetical. A STRONG nullifier in a genuine duration bound still fires on
two shapes in benign_toolcalls/discriminator.jsonl:

    archive_source(bucket="acme-archive", retention="forever", approval="LEGAL-88")
    create_licence(customer="acme", expires="never", contract="PERPETUAL-2024")

Both are routine. An archive bucket really is retained forever and a perpetual
licence really does not expire, and both say so in exactly the words an ASI04
attack uses — ``retention``/``expires`` are real bound keys and ``forever``/
``never`` are real strong nullifiers, so there is no lexical difference to read.
The ONLY thing separating them from an attack is the authorisation reference
sitting beside them (``LEGAL-88``, ``PERPETUAL-2024``), and that is app-supplied
and unsigned: an attacker types ``approval="LEGAL-88"`` as easily as the
archivist does. Reading it would not be a discrimination, it would be a
courtesy, so it is NOT read — the two flag, and this is written down instead.
That is the same reason scanner.privilege_action is FLAG rather than block.

FLAG, not block. An unbounded job is a cost and availability problem, not an
authorization boundary, and the failure mode of blocking a mis-read batch job in
production is worse than the failure mode of surfacing it. A deployer who wants
it hard has the policy engine; a deployer who wants observed fan-out has the
circuit breaker.
"""
from __future__ import annotations

import re
from typing import Iterable, Tuple

#: Same category as the existing LLM04 flood rules — this is the same OWASP
#: family (resource exhaustion / denial of service), and it is already a
#: recognised FLAG-tier tool-argument category, so no new tier plumbing.
CATEGORY = "dos_attempt"
_SCORE = 0.5  # flag band [flag_threshold=0.20, block_threshold=0.60)

#: A value of more than this many whitespace-separated words is PROSE (an
#: article body, a note), not a slot the caller filled with a bound. Not a
#: resource threshold — a scalar/prose discriminator.
_MAX_SLOT_WORDS = 4

# ── the value side: words that declare the absence of a ceiling ──────────────
# STRONG: the word means "no ceiling" and nothing else.
_NULLIFIER_STRONG = frozenset({
    "unlimited", "unbounded", "limitless", "uncapped", "unrestricted",
    "unthrottled", "unmetered", "boundless", "infinite", "infinity", "inf",
    "forever", "endless", "endlessly", "perpetual", "perpetually",
    "indefinite", "indefinitely", "never", "nonstop", "non-stop",
})
# WEAK: the word means "not set / turned off". Ambiguous on its own — a feature
# flag is legitimately "off" — so it only counts in a COST-BEARING bound slot
# (see _DURATION_MORPHEMES).
#
# "no" and "false" are NOT here, and neither is "yes"/"true": they are BOOLEAN
# LITERALS spelled as words, and a boolean is not read at all (see _BOOLEAN_WORDS
# and _slot_value). `over_budget: "no"` is a state report saying the budget held.
_NULLIFIER_WEAK = frozenset({
    "none", "off", "unset", "disabled", "disable",
    "null",  # the STRING "null"; JSON null is absence, see _slot_value
})

#: Booleans spelled as words. Excluded for the SAME reason as numeric sentinels
#: (see the module docstring): `rate_limit=false` removes a ceiling, while
#: `limit_reached=false` says the ceiling HELD, and `concurrent=false` is the
#: bounded direction outright. Telling those apart requires knowing which tool it
#: is — i.e. a tool list — so they are not read. Stated, not folded in.
_BOOLEAN_WORDS = frozenset({"true", "false", "yes", "no", "y", "n"})
# Multi-word nullifiers, matched against the WHOLE normalised value.
_NULLIFIER_PHRASE = re.compile(
    r"^no\s*(?:hard\s+|upper\s+)?"
    r"(?:limit|limits|cap|caps|ceiling|bound|bounds|max|maximum|quota|cutoff)$"
    r"|^without\s+(?:a\s+)?(?:limit|cap|ceiling|bound|maximum)$",
)

# ── the key side: two morpheme classes ───────────────────────────────────────
# BOUND: the slot names a CEILING. Nulling it removes the ceiling.
_BOUND_MORPHEMES = frozenset({
    "limit", "limits", "cap", "caps", "capped", "max", "maximum", "quota",
    "budget", "cost", "costs", "spend", "spending", "ttl", "retention",
    "retain", "timeout", "timeouts", "deadline", "expiry", "expires",
    "expiration", "threshold", "ceiling", "bound", "bounds", "rate",
    "ratelimit", "throttle", "throttling", "concurrency", "concurrent",
    "backoff", "cooldown", "lifetime",
})
#: The subset of _BOUND_MORPHEMES that names a DURATION, an AGE or an ALERT
#: LEVEL rather than a rate of spend. Nulling one of these consumes nothing:
#: `ttl: "none"` is a cache entry with no expiry, `deadline: "none"` is a
#: reminder with no due date, `threshold: "none"` alerts on every event. All
#: three are the commonest shape in production arguments — an OPTIONAL FIELD
#: LEFT UNSET — and none of them is denial-of-wallet.
#:
#: So these take only a STRONG nullifier, which is exactly the escalation
#: _EXTENT_MORPHEMES already gets and for the same reason: the weak class cannot
#: carry the claim on its own here. `retention: "forever"` and
#: `expires: "never"` still fire — see the RESIDUAL note at the end of this
#: module for why that is not obviously right either.
_DURATION_MORPHEMES = frozenset({
    "ttl", "retention", "retain", "timeout", "timeouts", "deadline",
    "expiry", "expires", "expiration", "threshold", "backoff", "cooldown",
    "lifetime",
})
#: Nominal qualifiers that turn a bound NOUN into a LABEL. `cost_center` is an
#: accounting dimension, `budget_code` a ledger reference, `limit_type` a
#: category name — none of them is a ceiling, and `cost_center: "none"` means
#: the expense is not yet allocated. A key carrying one of these is not read as
#: a bound however bound-shaped its other component is.
_LABEL_MORPHEMES = frozenset({
    "center", "centre", "code", "codes", "id", "ids", "uuid", "name", "names",
    "type", "types", "category", "group", "owner", "label", "tag", "tags",
    "ref", "reference", "unit", "department", "team", "project", "reason",
})
# EXTENT: the slot names HOW MUCH WORK. A number here is ordinary at any size,
# so only a STRONG nullifier counts.
_EXTENT_MORPHEMES = frozenset({
    "count", "counts", "instance", "instances", "replica", "replicas",
    "worker", "workers", "copy", "copies", "item", "items", "node", "nodes",
    "shard", "shards", "parallelism", "thread", "threads", "iteration",
    "iterations", "retry", "retries", "attempt", "attempts", "depth",
    "fanout", "scale", "batch", "batches", "request", "requests", "call",
    "calls", "token", "tokens", "page", "pages", "row", "rows", "record",
    "records", "size", "volume", "loops",
})

_KEY_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")
_WORD_SPLIT = re.compile(r"\s+")


def _key_parts(key: str) -> set:
    """Key components, lowercased. ``max_cost`` -> {max, cost};
    ``maxCost`` -> {max, cost}; ``strategy`` -> {strategy} (NOT a "rate" key —
    substring matching would make it one)."""
    return {p.lower() for p in _KEY_SPLIT.split(key) if p}


def _pairs(obj, key: str = "") -> Iterable[Tuple[str, object]]:
    """Every (key, value) pair, recursively. A list inherits its parent key, so
    ``limits: [..., "none"]`` is seen under ``limits``. Mirrors
    scanner.privilege_action._pairs."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _pairs(v, str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from _pairs(v, key)
    else:
        yield key, obj


def _slot_value(value) -> str | None:
    """The value normalised for reading as a SLOT, or None when it is not one.

    None (absence, and JSON null — which selects the default in most SDKs, so it
    is not a declaration that the bound is off), numbers, BOOLEANS in either
    polarity and spelled either way, and prose longer than ``_MAX_SLOT_WORDS``
    words are all not slots this reads.
    """
    if value is None or isinstance(value, (int, float)) and not isinstance(value, bool):
        return None
    if isinstance(value, bool):
        # Both polarities, for the reason given at _BOOLEAN_WORDS. `False` used
        # to normalise to the string "false" and reach the weak-nullifier set,
        # which read `limit_reached: False` — the ceiling HELD — as the ceiling
        # being removed.
        return None
    text = str(value).strip().lower()
    if not text or len(_WORD_SPLIT.split(text)) > _MAX_SLOT_WORDS:
        return None
    if text in _BOOLEAN_WORDS:
        return None
    return text


def _is_strong_nullifier(text: str) -> bool:
    return text in _NULLIFIER_STRONG or bool(_NULLIFIER_PHRASE.match(text))


def _is_nullifier(text: str) -> bool:
    return _is_strong_nullifier(text) or text in _NULLIFIER_WEAK


def scan_resource_bounds(tool_name: str, arguments) -> list:
    """Return findings [{rule, category, score}] for removed-bound shapes.

    ``tool_name`` is accepted for signature symmetry with the other structural
    scanners and is deliberately NOT used to decide anything.
    """
    if not isinstance(arguments, dict) or not arguments:
        return []
    findings: list = []

    def fire(rule: str):
        if not any(f["rule"] == rule for f in findings):
            findings.append({"rule": rule, "category": CATEGORY, "score": _SCORE})

    for key, value in _pairs(arguments):
        text = _slot_value(value)
        if text is None:
            continue
        parts = _key_parts(key)
        if parts & _LABEL_MORPHEMES:
            # A bound noun qualified into a label (cost_center, budget_code).
            # Not a ceiling at all, so neither branch below applies.
            continue
        if parts & _BOUND_MORPHEMES and (
            _is_strong_nullifier(text)
            or (text in _NULLIFIER_WEAK and not parts & _DURATION_MORPHEMES)
        ):
            # A ceiling the caller named and then removed. The weak class is
            # admitted only for the COST-BEARING bounds; a duration or an alert
            # level left unset is an optional field, not a removed ceiling.
            fire("ASI04_bound_removed")
        elif parts & _EXTENT_MORPHEMES and _is_strong_nullifier(text):
            # How much work to do, declared as "no ceiling". A NUMBER here — at
            # any size — is silent.
            fire("ASI04_unbounded_extent")

    return findings
