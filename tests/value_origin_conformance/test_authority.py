"""authority_of — the one normaliser (§6 C-6, V-10, V-19..V-23, rulings 3.2 / 3.6) —
and the linear-time property every pattern behind it must keep: it runs on
attacker-controlled values (open's ReDoS invariants)."""
from __future__ import annotations

import time

import pytest

from xaidr.value_origin import (
    Authority,
    bind_fresh_ledger,
    authority_of,
    extract_destinations,
    record_principal_input,
    record_tool_result,
    unbind_ledger,
)


def A(key):
    scheme, value = key.split(":", 1)
    return Authority(scheme=scheme, value=value)


@pytest.mark.parametrize("value,key", [
    # email (C-6, V-4, V-23)
    ("Bob.Reeves@Northbank.Example", "mailto:bob.reeves@northbank.example"),
    ("bob+x@corp.example", "mailto:bob+x@corp.example"),
    ("Bob <bob@corp.example>", "mailto:bob@corp.example"),
    ("mailto:bob@corp.example?subject=x", "mailto:bob@corp.example"),
    ("ops@münchen.example", "mailto:ops@xn--mnchen-3ya.example"),
    # URL -> registrable domain (C-6, V-10)
    ("https://docs.northbank.example/x", "dns:northbank.example"),
    ("https://a.b.github.io/", "dns:b.github.io"),
    ("https://www.example.co.uk/", "dns:example.co.uk"),
    ("https://s3.amazonaws.com/bucket", "dns:s3.amazonaws.com"),
    ("http://intranet/", "dns:intranet"),
    ("HTTPS://Corp.Example./", "dns:corp.example"),
    ("https://corp.example@evil.test/", "dns:evil.test"),
    ("https://evil.test\\@corp.example/", "dns:evil.test"),
    ("https://ev%69l.test/", "dns:evil.test"),
    ("https://pаypal.example/", "dns:xn--pypal-4ve.example"),
    ("https://xn--pypal-4ve.example/", "dns:xn--pypal-4ve.example"),
    ("https://ａｂｃ.example/", "dns:abc.example"),
    ("https://straße.example/", "dns:xn--strae-oqa.example"),
    ("evil.test/x", "dns:evil.test"),
    # IP (C-6, V-19, V-21)
    ("http://169.254.169.254/", "ip:169.254.169.254"),
    ("http://0xA9FEA9FE/", "ip:169.254.169.254"),
    ("http://2852039166/", "ip:169.254.169.254"),
    ("http://0251.0376.0251.0376/", "ip:169.254.169.254"),
    ("http://[::ffff:169.254.169.254]/", "ip:169.254.169.254"),
    ("http://[2001:DB8::1]/", "ip:2001:db8::1"),
    ("http://10.1/", "ip:10.0.0.1"),
    ("10.0.0.5", "ip:10.0.0.5"),
    ("::ffff:a9fe:a9fe", "ip:169.254.169.254"),
    # phone (V-22)
    ("+44 20 7123 4567", "tel:+442071234567"),
    ("+44 (0)20 7123 4567", "tel:+442071234567"),
    ("+1 (415) 555-0142", "tel:+14155550142"),
])
def test_authority_of_accepts(value, key):
    assert authority_of(value) == A(key)


@pytest.mark.parametrize("value", [
    "notes.md", "evil.test", "1.2.3", "4417", "report.v2/summary", "Bob Reeves",
    "file:///etc/passwd", "data:text/plain,hi", "mailto:", "+123", "+1234567890123456",
    "jürgen@corp.example", "a@b", "a@x.example, b@y.example", "", "   ",
    "https://" + "a" * 4_100 + ".example/",
])
def test_authority_of_rejects(value):
    assert authority_of(value) is None


def test_idna_failure_in_an_argument_still_yields_the_raw_host():
    """V-23: never no_destination; it matches only itself."""
    assert authority_of("https://a‍b.example/") == A("dns:a‍b.example")


# ── linear time on adversarial input ─────────────────────────────────────────
ADVERSARIAL = {
    "dots": "a." * 2_000,
    "at-runs": "a@" * 2_000,
    "email-ish": ("x" * 60 + "@") * 60,
    "scheme-runs": "http://" * 500,
    "plus-digits": "+1 " * 1_500,
    "colons": "1:" * 2_000,
    "hyphen-labels": ("-" * 60 + ".") * 60,
    "digits-dots": "1." * 2_000,
    "brackets": "(1)" * 1_300,
}


def _time(fn, n=3):
    best = float("inf")
    for _ in range(n):
        t = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t)
    return best


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_prose_and_argument_scans_grow_linearly(name):
    """Quadrupling the input must not cost more than ~12x (linear is 4x; the
    slack absorbs timer noise). A nested or ambiguous quantifier fails this."""
    unit = ADVERSARIAL[name]

    def cost(k):
        text = (unit * k)[:3_900 * k]

        def run():
            bind_fresh_ledger()
            record_principal_input(text, input_clean=True)
            record_tool_result("t", {}, text, designations=(), result_blocked=False)
            extract_destinations({"v": text[:3_999]})
        return _time(run)
    small, large = cost(1), cost(4)
    unbind_ledger()
    assert large < max(small * 12, 0.05), f"{name}: {small:.4f}s -> {large:.4f}s"
    assert large < 2.0, f"{name}: {large:.2f}s on 4x input"
