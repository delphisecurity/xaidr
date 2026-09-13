"""F8 (Sept 9 audit): a scanned prompt must not reach the logs via an
extension's own exception.

REPRODUCED ON 1.16.0 before any of this was written. A `SensorExtension` whose
`gate()` raised with the scan text in the message put that text on the sensor's
own ERROR line, verbatim and in full:

    xaidr: extension 'acme-quarantine' raised in gate() (ValueError: quarantine
    lookup failed for input 'please summarise this internal memo:
    PRIVATE_PROMPT_CANARY do not disclose'). THIS CONTROL IS INERT until ...

Four hooks reached that one sink and every one of them leaked: `gate`,
`transform_verdict`, `subject_trust`, `blocked_urls`. `escalation.run_escalators`
had the identical shape in its own file.

THE EXTENSION IS ENTITLED TO THE PROMPT. That is what `ScanRequest.text` is for.
The sensor's LOG is not, and `_extension_failed` shipped without the treatment
`_emit_scan_error` had had all along on the scan path four screens away.

WHY `safe_exc` IS NOT THE FIX, and why this file asserts that directly below.
`safe_exc` redacts URLs out of a message it otherwise keeps — right for a
reporter that failed against a destination, where the destination has a grammar
and is the diagnostic. An extension's exception text is arbitrary caller prose
with no grammar; there is no pattern separating the prompt from the diagnostic.
`test_safe_exc_would_NOT_have_fixed_this` is the discriminating case: it pins
that the tool the other paths use passes this canary through untouched.

The COUNT is the assertion, as in `test_audit_f8_reporter_redaction.py`: every
test asserts ZERO occurrences across logging, stdout and stderr — and, in the
same breath, that the line is still USABLE (names the extension, the hook and
the exception type). A sink made safe by going silent is not a fix.
"""

from __future__ import annotations

import io
import logging
import sys

import pytest

from xaidr import Sensor
from xaidr.escalation import Escalator, run_escalators
from xaidr.extensions import ScanRequest, SensorExtension
from xaidr.reporters import exc_origin, safe_exc, safe_fault
from xaidr.types import ScanResult

CANARY = "PRIVATE_PROMPT_CANARY"
PROMPT = f"please summarise this internal memo: {CANARY} do not disclose"


class _NullReporter:
    """No telemetry sink at all — so anything captured came from a LOG."""

    def report(self, *a, **k): ...
    def close(self, *a, **k): ...


class _Capture:
    """Everything a fault could write: the xaidr loggers, stdout, stderr.

    The handler is attached to the ``xaidr`` PARENT logger, so a sink added in
    any submodule is captured without this file having to know its name — which
    is the whole point of a regression test for "one path was added without the
    treatment the others had".
    """

    def __enter__(self):
        self.buf = io.StringIO()
        self._handler = logging.StreamHandler(self.buf)
        self._handler.setLevel(logging.DEBUG)
        self._logger = logging.getLogger("xaidr")
        self._level = self._logger.level
        self._propagate = self._logger.propagate
        self._logger.addHandler(self._handler)
        self._logger.setLevel(logging.DEBUG)
        self._out, self._err = sys.stdout, sys.stderr
        self._so, self._se = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = self._so, self._se
        return self

    def __exit__(self, *exc):
        sys.stdout, sys.stderr = self._out, self._err
        self._logger.removeHandler(self._handler)
        self._logger.setLevel(self._level)
        self._logger.propagate = self._propagate
        return False

    @property
    def text(self) -> str:
        return self.buf.getvalue() + self._so.getvalue() + self._se.getvalue()

    def counts(self) -> dict:
        return {
            "logging": self.buf.getvalue().count(CANARY),
            "stdout": self._so.getvalue().count(CANARY),
            "stderr": self._se.getvalue().count(CANARY),
        }

    def assert_clean(self, what: str):
        c = self.counts()
        total = sum(c.values())
        assert total == 0, (
            f"{what}: the scanned prompt leaked. The canary appears {total} "
            f"time(s) in sensor-owned output "
            f"(logging={c['logging']} stdout={c['stdout']} stderr={c['stderr']}"
            ").\n--- captured ---\n" + self.text + "\n---"
        )

    def assert_still_useful(self, *needles: str):
        """A sink made safe by saying nothing is not a fix."""
        for needle in needles:
            assert needle in self.text, (
                f"the fault line no longer names {needle!r}, so an operator "
                f"cannot act on it.\n--- captured ---\n{self.text}\n---"
            )


# ── the tool choice, argued as a test ────────────────────────────────────────

def test_safe_exc_would_NOT_have_fixed_this():
    """THE DISCRIMINATING CASE for (b).

    `safe_exc` is what every reporter path uses and it is the obvious thing to
    reach for here. It does not work: the reporter leak was a URL, which has a
    grammar `redact_url` can take apart. This leak is a prompt. `safe_exc`
    passes it through in full, and a fix built on it would have been green,
    plausible, and still leaking.
    """
    out = safe_exc(ValueError(f"gate failed on {PROMPT!r}"))
    assert CANARY in out, (
        "safe_exc has changed and now strips arbitrary text; if that is "
        "deliberate, this file's argument for safe_fault needs rewriting"
    )
    assert out.startswith("ValueError:")


def test_safe_fault_keeps_the_type_and_the_location_and_drops_the_message():
    try:
        raise ValueError(f"gate failed on {PROMPT!r}")
    except ValueError as exc:
        out = safe_fault(exc)
    assert CANARY not in out, out
    assert out.startswith("ValueError at "), out
    # The location is THIS module and a real line — derived from code objects,
    # never from input. That is the actionable half a type alone does not give.
    assert __name__ in out, out
    assert out.rsplit(":", 1)[1].isdigit(), out


def test_safe_fault_survives_an_exception_with_no_traceback():
    out = safe_fault(RuntimeError(PROMPT))
    assert CANARY not in out, out
    assert out == "RuntimeError at unknown", out


def test_safe_fault_and_exc_origin_never_raise():
    class Exploding(Exception):
        def __str__(self):
            raise ValueError("boom")

    assert isinstance(safe_fault(Exploding()), str)
    assert isinstance(exc_origin(Exploding()), str)


def test_exc_origin_is_bounded():
    """An unbounded log field is an unbounded log field, even a safe one."""
    try:
        raise ValueError("x")
    except ValueError as exc:
        assert len(exc_origin(exc)) <= 120


# ── the three hooks named in the finding ─────────────────────────────────────

class _GateBoom(SensorExtension):
    """A real quarantine gate: it looks at the scan text, and the lookup it
    builds out of that text raises with the subject echoed back — which is what
    json, re, pydantic and every HTTP client do."""

    name = "acme-quarantine"

    def gate(self, req):
        raise ValueError(f"quarantine lookup failed for input {req.text!r}")


class _TransformBoom(SensorExtension):
    name = "acme-fleet-mode"

    def transform_verdict(self, req, result):
        raise RuntimeError(f"fleet mode lookup failed for input {req.text!r}")


class _AttachBoom(SensorExtension):
    name = "acme-attach"

    def on_attach(self, sensor):
        raise RuntimeError(f"attach failed loading config {PROMPT!r}")


def test_gate_exception_does_not_put_the_prompt_in_the_log():
    with _Capture() as cap:
        s = Sensor(agent_id="f8", enforcement_mode="block",
                   reporter=_NullReporter(), extensions=[_GateBoom()])
        result = s.scan(PROMPT)
    cap.assert_clean("gate()")
    cap.assert_still_useful("acme-quarantine", "gate()", "ValueError")
    # The fail-safe contract is untouched: the scan still completed.
    assert result.action in ("allowed", "flagged", "blocked")


def test_verdict_transform_exception_does_not_put_the_prompt_in_the_log():
    with _Capture() as cap:
        s = Sensor(agent_id="f8", enforcement_mode="block",
                   reporter=_NullReporter(), extensions=[_TransformBoom()])
        s.scan(PROMPT)
    cap.assert_clean("transform_verdict()")
    cap.assert_still_useful("acme-fleet-mode", "transform_verdict()",
                            "RuntimeError")


def test_on_attach_exception_does_not_put_the_payload_in_the_log():
    """`on_attach` still RAISES — that contract is not being changed here.

    What changed is that the sensor now says something on the way out, under
    the same content rule as the other hooks, so a host that catches the
    constructor exception and falls back to an unprotected path still leaves a
    record. The exception itself carries the message to the CALLER, who owns the
    disclosure decision for their own logging boundary.
    """
    with _Capture() as cap:
        with pytest.raises(RuntimeError) as raised:
            Sensor(agent_id="f8", enforcement_mode="block",
                   reporter=_NullReporter(), extensions=[_AttachBoom()])
    cap.assert_clean("on_attach()")
    cap.assert_still_useful("acme-attach", "on_attach()", "RuntimeError")
    # ... and the caller still gets the real thing.
    assert CANARY in str(raised.value), (
        "the re-raise was swallowed or rewritten; the caller can no longer "
        "reach the message at their own boundary"
    )


# ── the neighbours the audit asked for ───────────────────────────────────────

class _TrustBoom(SensorExtension):
    name = "acme-trust"

    def subject_trust(self, agent_id):
        raise RuntimeError(f"trust lookup failed for {PROMPT!r}")


class _BlocklistBoom(SensorExtension):
    name = "acme-blocklist"

    def blocked_urls(self):
        raise RuntimeError(f"feed refresh failed: upstream said {PROMPT!r}")


def test_subject_trust_exception_does_not_put_caller_text_in_the_log():
    with _Capture() as cap:
        s = Sensor(agent_id="f8", reporter=_NullReporter(),
                   extensions=[_TrustBoom()])
        assert s._subject_trust("f8") is None
    cap.assert_clean("subject_trust()")
    cap.assert_still_useful("acme-trust", "subject_trust()", "RuntimeError")


def test_blocked_urls_exception_does_not_put_caller_text_in_the_log():
    with _Capture() as cap:
        s = Sensor(agent_id="f8", reporter=_NullReporter(),
                   extensions=[_BlocklistBoom()])
        s.effective_blocked_urls()
    cap.assert_clean("blocked_urls()")
    cap.assert_still_useful("acme-blocklist", "blocked_urls()", "RuntimeError")


class _EscalatorBoom(Escalator):
    """S3's version of the same shape: `scan` is handed `req.text` too."""

    name = "acme-link"

    def scan(self, req, local_result):
        raise RuntimeError(f"link rejected the payload {req.text!r}")


def test_escalator_exception_does_not_put_the_prompt_in_the_log():
    local = ScanResult(action="flagged", score=0.3, category="test",
                       rules=["R"], latency_ms=0)
    req = ScanRequest(agent_id="f8", direction="input", text=PROMPT)
    with _Capture() as cap:
        result, escalation, reason = run_escalators([_EscalatorBoom()], req,
                                                    local)
    cap.assert_clean("escalator scan()")
    cap.assert_still_useful("acme-link", "RuntimeError")
    # The skip contract is untouched.
    assert result is local
    assert escalation == "skipped" and reason == "acme-link_unreachable"


def test_breaker_on_trip_exception_does_not_put_caller_text_in_the_log():
    """`on_trip` is arbitrary HOST code and fires from inside a scan."""
    from xaidr.circuit_breaker import CircuitBreaker, _CircuitRuntime

    def boom(payload):
        raise RuntimeError(f"alerting failed while handling {PROMPT!r}")

    runtime = _CircuitRuntime(
        CircuitBreaker(violation_threshold=1, on_trip=boom), "f8", "block")
    with _Capture() as cap:
        runtime._fire_on_trip({"reason": "violation_threshold"})
    cap.assert_clean("circuit_breaker on_trip")
    cap.assert_still_useful("on_trip", "RuntimeError")


def test_s2_condition_evaluator_exception_does_not_put_request_text_in_the_log():
    """The S2 seam: the evaluator is extension code and sees the request."""
    from xaidr.local_policy import evaluate_policy, set_policy_dict

    def boom(request, value):
        raise RuntimeError(
            f"region lookup failed for {request['resource']['destination_identifier']!r}"
        )

    policy = set_policy_dict(
        {"version": "1",
         "defaults": {"effect": "allow", "unclassified": "allow"},
         "rules": [{"id": "r1", "effect": "block",
                    "match": {"tools": ["http_post"]},
                    "conditions": {"region_is": "EU"}}]},
        extra_conditions={"region_is": boom},
    )
    assert policy is not None, "policy with a registered condition was rejected"
    with _Capture() as cap:
        evaluate_policy(
            policy, agent_id="f8", trust=None, tool_name="http_post",
            impact_class="network_egress", impact_tier="high",
            destination_type="url", destination_identifier=PROMPT,
        )
    cap.assert_clean("S2 condition evaluator")
    cap.assert_still_useful("region_is", "RuntimeError")


# ── the sinks the audit cleared, pinned so they stay cleared ─────────────────

def test_escalator_health_keeps_its_message_because_it_cannot_see_content():
    """The other half of the (b) decision, pinned.

    `health()` takes no arguments and runs at CONSTRUCTION, before any scan, so
    its message cannot echo scanned content. What it DOES carry is the backend
    URL the link could not reach — the useful half of the diagnostic, and
    exactly the shape `safe_exc` strips the credential out of. This test exists
    so a later sweep that replaces every `safe_exc` with `safe_fault` has to
    argue with something rather than silently cost an operator the reason their
    link is down.
    """
    from xaidr.scanner.local import LocalScanner

    class _HealthBoom(Escalator):
        name = "acme-link"

        def health(self):
            raise RuntimeError(
                "connection refused to https://brain.example.com/scan?token=SEKRIT")

    with _Capture() as cap:
        LocalScanner(escalators=(_HealthBoom(),))
    text = cap.text
    assert "SEKRIT" not in text, f"safe_exc did not redact the query value:\n{text}"
    assert "brain.example.com" in text, (
        f"the destination diagnostic was lost:\n{text}")
    assert "connection refused" in text, (
        f"the message was dropped; health() has no content path and does not "
        f"need safe_fault:\n{text}")
