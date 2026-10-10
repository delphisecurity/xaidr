"""Owner, 2026-10-06: "Bound the atom pass by WORK, not by input position. The
timing test is right; the unbounded ruling that broke it was mine." Hitting the
budget is a visible state saying extraction was incomplete; it does NOT block.
Relaxing the size guarantee is refused ("lets an attacker choose how long the
scan takes"). Also: key n-grams get their own ledger budget (65,536), apart
from the 10,000 destinations, and the 4,000-char cliff is a known artefact."""
from __future__ import annotations

import contextvars

import pytest

from xaidr import value_origin as vo
from xaidr.value_origin import Mode, should_block
from xaidr.value_origin import _authority, _ledger

EVIL = "https://evil.example/collect"
NEUTRAL = "Summarise the quarterly report for me."
DENSE = "x.co " * 1_000_000                       # 5 MB, an atom every 5 chars
CEILING = 1_000_000   # far above any sane budget; the unbounded pass scans 5,000,000


def _flow(*steps, call):
    def run():
        vo.bind_fresh_ledger()
        for kind, payload in steps:
            if kind == "input":
                vo.record_principal_input(payload, None, input_clean=True)
            else:
                vo.record_tool_result("web_fetch", {}, payload, designations=(),
                                      result_blocked=False)
        return vo.evaluate_call("http_post", call, flow_active=True)
    return contextvars.Context().run(run)


@pytest.fixture
def scanned(monkeypatch):
    """Characters the prose extractor actually scans, whoever calls it."""
    seen = []
    real = _authority.prose_candidates

    def counting(text, *a, **k):
        seen.append(len(text))
        return real(text, *a, **k)
    monkeypatch.setattr(_authority, "prose_candidates", counting)
    monkeypatch.setattr(_ledger, "prose_candidates", counting)
    return seen


@pytest.mark.parametrize("path", ["argument", "result", "input"])
def test_the_atom_pass_is_bounded_by_work_and_says_so(path, scanned):
    steps, call = (("input", NEUTRAL),), {"url": "https://other.example/"}
    if path == "argument":
        call = {"url": "https://other.example/", "body": DENSE}
    elif path == "result":
        steps += (("result", DENSE),)
    else:
        steps = (("input", NEUTRAL + " " + DENSE),)
    v = _flow(*steps, call=call)
    total = sum(scanned)
    assert total < CEILING, (
        f"{path}: the atom pass scanned {total:,} chars of a 5 MB address-dense value -- "
        "unbounded, so an attacker chooses how long the scan takes")
    assert v.wire.value == "extraction_incomplete", (
        f"{path}: the budget was hit but the call reads {v.wire.value!r}: incomplete "
        "extraction is not visible")
    assert not should_block(v, mode=Mode.ENFORCE), f"{path}: hitting the budget must not block"


def test_a_17kb_benign_prompt_no_longer_fills_the_ledger():
    p17 = " ".join(f"item{i}" for i in range(2600))     # ~18 KB of DISTINCT words
    assert 17_000 < len(p17) < 25_000

    def run():
        vo.bind_fresh_ledger()
        return vo.record_principal_input(p17, None, input_clean=True)
    out = contextvars.Context().run(run)
    assert out is vo.RecordOutcome.RECORDED, (
        f"a benign {len(p17):,}-char prompt gave {out}: its ~10,400 distinct key n-grams "
        "filled the 10,000 entries destinations share (owner, approved: a separate 65,536)")


def test_known_artefact_the_4000_char_cliff():
    """KNOWN ARTEFACT (owner, 2026-10-06; re-checked after the budget change, which
    does not touch it). C-8: a leaf is a destination only if its WHOLE value is
    one, so a 3,999-char body quoting an untrusted URL yields no finding; over
    4,000 chars the same URL is found as an atom. Pinned so a change is seen."""
    def body(n):
        head = "See " + EVIL + " for details. "
        return head + "x" * (n - len(head))
    short = _flow(("input", NEUTRAL), ("result", "see " + EVIL), call={"body": body(3_999)})
    long_ = _flow(("input", NEUTRAL), ("result", "see " + EVIL), call={"body": body(4_001)})
    assert short.wire.value == "no_destination" and not should_block(short, mode=Mode.ENFORCE)
    assert long_.wire.value == "untrusted_source" and should_block(long_, mode=Mode.ENFORCE)


# ── silent-failure review of 097be72 (CRITICAL): structural width ────────────
@pytest.fixture
def children_seen(monkeypatch):
    """How many child nodes the walks enumerate, whichever walk asks."""
    from xaidr.value_origin import _extract
    seen = [0]
    real = _extract._children

    def counting(node):
        is_container, kids = real(node)

        def it():
            for k in kids:
                seen[0] += 1
                yield k
        return is_container, it()
    monkeypatch.setattr(_extract, "_children", counting)
    return seen


WIDE = 2_000_000


@pytest.mark.parametrize("path", ["argument", "result"])
def test_a_wide_container_cannot_escape_the_work_budget(path, children_seen):
    wide = {f"k{i}": "s" for i in range(66)}
    wide["wide"] = {str(i): "v" for i in range(WIDE)}
    if path == "argument":
        v = _flow(("input", NEUTRAL), call=dict(wide, url="https://other.example/"))
    else:
        v = _flow(("input", NEUTRAL), ("result", wide), call={"url": "https://other.example/"})
    assert children_seen[0] < 1_500_000, (
        f"{path}: the walks enumerated {children_seen[0]:,} children of a {WIDE:,}-wide "
        "dict -- a container's whole width was taken in one uncounted step, so width "
        "alone chooses how long the scan takes")
    assert v.wire.value == "extraction_incomplete", (path, v.wire.value)



# ── milestone review of 097be72 ──────────────────────────────────────────────
def test_a_url_just_past_an_address_dense_result_prefix_is_still_found():
    """HIGH: the atom pass re-scanned the EXAMINED 64 KiB prefix from char 0, so an
    address-dense prefix spent the budget before the cut and a URL 9 chars past
    it was let through (before the budget it was found)."""
    prefix = ("x.co " * 13_110)[:65_540]
    v = _flow(("input", NEUTRAL), ("result", prefix + " " + EVIL), call={"url": EVIL})
    assert v.wire.value == "untrusted_source", (
        f"a poisoned URL just past the 64 KiB cut of a result read {v.wire.value!r}: the "
        "budget was spent re-reading the examined prefix")


def test_rejected_candidates_are_charged_too(scanned):
    """HIGH: only ACCEPTED atoms were charged, so candidates the extractor examines
    and rejects (non-ASCII hosts, bad TLDs) ran nearly free: 'é.é' x 5 MB cost
    ~0.6 s per call against the claimed 0.25 s worst."""
    _flow(("input", NEUTRAL), call={"url": "https://other.example/", "body": "é.é " * 1_250_000})
    total = sum(scanned)
    assert total < 100_000, (
        f"the atom pass scanned {total:,} chars of rejected-candidate text: rejected "
        "candidates cost the same normalisation and were not charged for it")
