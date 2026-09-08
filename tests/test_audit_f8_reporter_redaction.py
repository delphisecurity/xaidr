"""F8: a credential in a reporter destination must not reach the logs.

REPRODUCED ON 1.12.0 before any of this was written. A WebhookReporter whose URL
carried `?token=<canary>` failed against a mock 500 and the canary appeared
TWICE on one log line:

    WebhookReporter failed to deliver 1 events to https://host/ingest?token=CANARY:
    Server error '500 Internal Server Error' for url 'https://host/ingest?token=CANARY'

That is the finding the second verifier made, and it is why a partial fix is
worse than none: THE URL AND THE EXCEPTION ARE SEPARATE SINKS. Redacting
`self._url` alone leaves the credential in httpx's own message, which repeats the
full request URL. The COUNT is the assertion here, not the presence: every test
below asserts the canary appears ZERO times across logging, stdout and stderr.

Every reporter is covered, not only the webhook one, because the shape is
"identifier plus exception on failure" and five other places have it -- including
the telemetry queue's outer catch, which sees exceptions from ANY reporter.
"""

from __future__ import annotations

import io
import logging
import sys

import pytest

from xaidr.reporters import (
    FileReporter,
    MultiReporter,
    OTelReporter,
    StdoutReporter,
    redact_text,
    redact_url,
    safe_exc,
)

CANARY = "s3cr3t-CANARY-token-9f2a"
QUERY_URL = f"https://collector.example.com/ingest?token={CANARY}&team=ops"
USERINFO_URL = f"https://svc:{CANARY}@collector.example.com/ingest"


class _Capture:
    """Everything a failure could write: the xaidr loggers, stdout, stderr."""

    def __enter__(self):
        self.buf = io.StringIO()
        self._handler = logging.StreamHandler(self.buf)
        self._handler.setLevel(logging.DEBUG)
        self._loggers = [logging.getLogger("xaidr"),
                         logging.getLogger("xaidr.reporters"),
                         logging.getLogger("xaidr.telemetry")]
        self._levels = []
        for lg in self._loggers:
            self._levels.append(lg.level)
            lg.addHandler(self._handler)
            lg.setLevel(logging.DEBUG)
        self._out, self._err = sys.stdout, sys.stderr
        self._so, self._se = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = self._so, self._se
        return self

    def __exit__(self, *exc):
        sys.stdout, sys.stderr = self._out, self._err
        for lg, lvl in zip(self._loggers, self._levels):
            lg.removeHandler(self._handler)
            lg.setLevel(lvl)
        return False

    @property
    def text(self) -> str:
        return self.buf.getvalue() + self._so.getvalue() + self._se.getvalue()

    def assert_clean(self, what: str):
        n = self.text.count(CANARY)
        assert n == 0, (
            f"{what}: the credential appears {n} time(s) in captured output.\n"
            f"---\n{self.text}\n---"
        )


# ── the sanitisers themselves ────────────────────────────────────────────────

@pytest.mark.parametrize("url,keep", [
    (QUERY_URL, "collector.example.com"),
    (USERINFO_URL, "collector.example.com"),
    (f"https://h.example.com/p?a={CANARY}#frag{CANARY}", "h.example.com"),
])
def test_redact_url_removes_the_secret_and_keeps_the_destination(url, keep):
    out = redact_url(url)
    assert CANARY not in out, out
    assert keep in out, f"redaction destroyed the diagnostic value: {out}"


def test_redact_url_keeps_query_keys():
    """Knowing the call carried a `token` parameter is diagnostic; knowing its
    value is the leak. The key must survive."""
    out = redact_url(QUERY_URL)
    assert "token=" in out and "team=" in out, out
    assert CANARY not in out


@pytest.mark.parametrize("value", ["/var/log/xaidr.jsonl", "not a url at all",
                                   "", None, 12345])
def test_redact_url_passes_through_things_that_are_not_urls(value):
    """A FileReporter path must stay readable. Never raises."""
    out = redact_url(value)
    assert isinstance(out, str)
    if isinstance(value, str) and value:
        assert out == value


def test_redact_text_finds_a_url_inside_a_sentence():
    out = redact_text(f"Server error '500' for url '{QUERY_URL}' see docs")
    assert CANARY not in out
    assert "collector.example.com" in out and "Server error" in out


def test_safe_exc_names_the_type_and_redacts_the_message():
    out = safe_exc(RuntimeError(f"failed talking to {QUERY_URL}"))
    assert out.startswith("RuntimeError:")
    assert CANARY not in out
    assert "collector.example.com" in out


def test_the_sanitisers_never_raise():
    class Exploding:
        def __str__(self):
            raise ValueError("boom")

    assert isinstance(redact_url(Exploding()), str)
    assert isinstance(redact_text(Exploding()), str)
    assert isinstance(safe_exc(RuntimeError("x")), str)


# ── WebhookReporter: the reported case, both credential shapes ───────────────

def _webhook_failing(url, handler=None):
    httpx = pytest.importorskip("httpx")
    from xaidr.reporters import WebhookReporter

    reporter = WebhookReporter(url)
    reporter._client = httpx.Client(transport=httpx.MockTransport(
        handler or (lambda rq: httpx.Response(500, text="boom"))))
    return reporter


@pytest.mark.parametrize("url,shape", [
    (QUERY_URL, "query parameter"),
    (USERINFO_URL, "userinfo"),
])
def test_webhook_failure_does_not_log_the_credential(url, shape):
    reporter = _webhook_failing(url)
    with _Capture() as cap:
        reporter.report([{"event": "test", "action": "blocked"}])
    cap.assert_clean(f"WebhookReporter with the credential in the {shape}")


def test_webhook_failure_still_says_where_it_failed():
    """Non-vacuity. A redaction that logged nothing would pass every assertion
    above and leave an operator unable to diagnose a delivery failure."""
    reporter = _webhook_failing(QUERY_URL)
    with _Capture() as cap:
        reporter.report([{"event": "test"}])
    assert "collector.example.com" in cap.text, cap.text
    assert "WebhookReporter" in cap.text
    assert "500" in cap.text, "the failure cause is gone from the log line"


def test_webhook_connection_error_also_redacts():
    """A transport-level failure is a different exception type carrying the same
    URL, so it is a separate path through the same sink."""
    httpx = pytest.importorskip("httpx")

    def boom(request):
        raise httpx.ConnectError(f"failed to connect to {QUERY_URL}")

    reporter = _webhook_failing(QUERY_URL, handler=boom)
    with _Capture() as cap:
        reporter.report([{"event": "test"}])
    cap.assert_clean("WebhookReporter on a connection error")


# ── every other reporter ────────────────────────────────────────────────────

def test_stdout_reporter_failure_does_not_log_a_credential():
    class Exploding:
        def write(self, _):
            raise OSError(f"stream died writing to {QUERY_URL}")

    with _Capture() as cap:
        StdoutReporter(stream=Exploding()).report([{"event": "test"}])
    cap.assert_clean("StdoutReporter")


def test_file_reporter_failure_does_not_log_a_credential(tmp_path):
    """The path is an identifier logged on failure, exactly like the webhook
    URL, and the exception carries whatever the OS put in it."""
    reporter = FileReporter(str(tmp_path / "events.jsonl"))

    class Exploding:
        def write(self, _):
            raise OSError(f"disk gone, spooling to {QUERY_URL}")

        def flush(self):
            pass

    reporter._path = QUERY_URL          # the identifier half of the sink
    reporter._fh = Exploding()          # the exception half
    with _Capture() as cap:
        reporter.report([{"event": "test"}])
    cap.assert_clean("FileReporter")


def test_otel_reporter_failure_does_not_log_a_credential():
    reporter = OTelReporter.__new__(OTelReporter)

    class Boom:
        def emit(self, *a, **k):
            raise RuntimeError(f"otel pipeline down, endpoint {QUERY_URL}")

    reporter._logger = Boom()
    reporter._schema = None
    with _Capture() as cap:
        reporter.report([{"event": "test"}])
    cap.assert_clean("OTelReporter")


def test_multi_reporter_failure_does_not_log_a_credential():
    """MultiReporter catches whatever a child raises, so a child that does NOT
    swallow hands it the full exception."""
    class Raising:
        def report(self, events):
            raise RuntimeError(f"delivery to {QUERY_URL} failed")

        def close(self):
            pass

    with _Capture() as cap:
        MultiReporter(Raising()).report([{"event": "test"}])
    cap.assert_clean("MultiReporter")


def test_the_telemetry_queue_outer_catch_does_not_log_a_credential():
    """The last sink, and the one easiest to miss.

    SyncTelemetryQueue._flush wraps EVERY reporter, so an exception escaping any
    of them lands here with whatever URL it carries. The shipped reporters all
    swallow their own errors, which is exactly why this path is easy to believe
    unreachable -- a CUSTOM reporter, which this project explicitly supports as a
    one-line plug-in, has no such obligation.
    """
    from xaidr.telemetry import SyncTelemetryQueue, _WorkerState

    class Raising:
        def report(self, events):
            raise RuntimeError(f"delivery to {QUERY_URL} failed")

        def close(self):
            pass

    state = _WorkerState(Raising(), 10, 1.0)
    with _Capture() as cap:
        SyncTelemetryQueue._flush(state, [{"event": "test"}])
    cap.assert_clean("telemetry queue outer catch")
    assert "dropping 1 events" in cap.text, "the diagnostic was lost entirely"
