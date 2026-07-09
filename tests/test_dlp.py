"""Smoke coverage for DLP (xaidr/scanner/dlp.py) + the reserved-domain rule.

All secret/PII samples below are OBVIOUSLY FAKE test values (AWS's own published
example key, a 555-style SSN placeholder) — never real secrets.

Note (observed): a *single* email is not a raw-DLP finding; the reserved-vs-real
email distinction lives at the SENSOR output-L1 layer (rule ``OUT_pii_email``),
so that case is exercised through ``scan_output``.
"""

from __future__ import annotations

from xaidr.scanner import dlp


# ── module-level DLP ─────────────────────────────────────────────────────────
def test_fake_ssn_detected():
    r = dlp.scan_dlp("my ssn is 123-45-6789")
    assert r.triggered is True
    assert any(t.category == "pii_ssn" for t in r.threats)


def test_fake_aws_key_detected():
    # AWS's own documentation example key — a known-fake placeholder.
    r = dlp.scan_dlp("the key is AKIAIOSFODNN7EXAMPLE")
    assert r.triggered is True
    assert any(t.category == "secret_aws_key" for t in r.threats)


def test_clean_string_no_findings():
    r = dlp.scan_dlp("the weather is nice today")
    assert r.triggered is False
    assert r.threats == []


def test_bulk_email_exfiltration_detected():
    bulk = "leak: " + " ".join(f"user{i}@corp.com" for i in range(10))
    r = dlp.scan_dlp(bulk)
    assert r.triggered is True
    assert any(t.rule == "DLP_email_bulk" for t in r.threats)


# ── reserved-domain rule via the Sensor output path ──────────────────────────
def test_reserved_domain_email_not_flagged(sensor):
    # example.com is an RFC-reserved documentation domain -> NOT PII.
    assert sensor.scan_output("contact admin@example.com for the sample").action == (
        "allowed"
    )


def test_real_domain_email_flagged(sensor):
    # A real-looking corp domain IS treated as PII on the output path.
    assert sensor.scan_output("send it to real_target@corp.com").action != "allowed"
