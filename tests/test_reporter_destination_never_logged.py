"""Reporter destination URLs are never written to logs, by any logger.

The invariant is checked at the ROOT logger, not only on ``xaidr.*``, because
two of the lines that can name a destination are not this package's own:

1. HTTPX'S REQUEST LINE. httpx logs ``HTTP Request: POST <url> "<status>"`` at
   INFO on the ``httpx`` logger for every request a client sends, success or
   failure. A host that enables INFO logging
   (``logging.basicConfig(level=logging.INFO)`` is enough) receives that line,
   so it must carry the destination redacted: Slack and Discord path tokens,
   query values and userinfo passwords never appear in it.

2. THE REPORTER'S OWN FAILURE LINE, ON EVERY SPELLING OF THE DESTINATION. The
   exception text is scrubbed of the configured destination however a library
   spells it: without a scheme, with a non-numeric port, with a ``)`` or ``'``
   in the path, or with a query longer than the URL pattern's 2000-character
   bound.

Each invariant test asserts the canary count is ZERO across every logger,
stdout and stderr. The non-vacuity tests below them assert the lines still exist
and still name the host, so an implementation that silenced logging would fail
here too.
"""

from __future__ import annotations

import io
import logging
import sys

import pytest

httpx = pytest.importorskip("httpx")

from xaidr.reporters import WebhookReporter  # noqa: E402

CANARY = "s3cr3t-CANARY-token-9f2a"

#: The destination shapes a WebhookReporter is pointed at, canary substituted
#: for the secret.
DESTINATIONS = {
    "slack path": f"https://hooks.slack.com/services/T0A1B2C3/B9Z8Y7X6/{CANARY}",
    "discord path": f"https://discord.com/api/webhooks/1104857392017/{CANARY}",
    "query value": f"https://collector.example.com/ingest?token={CANARY}&team=ops",
    "userinfo": f"https://svc:{CANARY}@collector.example.com/ingest",
}

#: Destinations the URL regex alone does not take apart.
AWKWARD = {
    "no scheme": f"hooks.slack.com/services/T0A1B2C3/B9Z8Y7X6/{CANARY}",
    "token in the port": f"https://collector.example.com:{CANARY}/ingest",
    "paren in the path": f"https://collector.example.com/a)b/{CANARY}",
    "quote in the path": f"https://collector.example.com/a'b/{CANARY}",
    "query past the regex bound": (
        f"https://collector.example.com/ingest?pad={'a' * 2100}&token={CANARY}"),
}


class _RootCapture:
    """Every log record from every logger, plus stdout and stderr.

    The root logger is set to DEBUG and the ``httpx`` logger is left at its
    own level, so its INFO request line propagates exactly as it does in a
    host that called ``logging.basicConfig(level=logging.INFO)``.
    """

    def __enter__(self):
        self.buf = io.StringIO()
        self._handler = logging.StreamHandler(self.buf)
        self._handler.setLevel(logging.DEBUG)
        self._handler.setFormatter(
            logging.Formatter("%(name)s %(levelname)s %(message)s"))
        self._root = logging.getLogger()
        self._level = self._root.level
        self._root.addHandler(self._handler)
        self._root.setLevel(logging.DEBUG)
        self._out, self._err = sys.stdout, sys.stderr
        self._so, self._se = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = self._so, self._se
        return self

    def __exit__(self, *exc):
        sys.stdout, sys.stderr = self._out, self._err
        self._root.removeHandler(self._handler)
        self._root.setLevel(self._level)
        return False

    @property
    def text(self) -> str:
        return self.buf.getvalue() + self._so.getvalue() + self._se.getvalue()

    def assert_clean(self, what: str) -> None:
        n = self.text.count(CANARY)
        lines = [ln[:300] for ln in self.text.splitlines() if CANARY in ln]
        assert n == 0, (
            f"{what}: the webhook credential appears in log output {n} "
            f"time(s); the invariant is zero. Anyone who can read these logs "
            f"could post to the webhook.\n"
            + "\n".join(lines)
        )


def _reporter(url: str, status: int) -> WebhookReporter:
    reporter = WebhookReporter(url)
    reporter._client.close()
    reporter._client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(status, text="body")))
    return reporter


# ── sink 1: httpx's own request line ────────────────────────────────────────

@pytest.mark.parametrize("status", [200, 500])
@pytest.mark.parametrize("shape", sorted(DESTINATIONS))
def test_httpx_request_line_does_not_carry_the_credential(shape, status):
    reporter = _reporter(DESTINATIONS[shape], status)
    try:
        with _RootCapture() as cap:
            reporter.report([{"event": "test"}])
    finally:
        reporter.close()
    cap.assert_clean(f"WebhookReporter ({shape}, HTTP {status})")


def test_httpx_request_line_still_names_the_destination():
    """Non-vacuity: the line is rewritten, not dropped, and keeps the host."""
    reporter = _reporter(DESTINATIONS["slack path"], 200)
    try:
        with _RootCapture() as cap:
            reporter.report([{"event": "test"}])
    finally:
        reporter.close()
    lines = [ln for ln in cap.text.splitlines() if ln.startswith("httpx ")]
    assert lines, f"httpx's request line is gone entirely:\n{cap.text}"
    assert "hooks.slack.com" in lines[0] and "200" in lines[0], lines[0]


def test_an_unrelated_httpx_request_is_logged_unchanged():
    """The redaction is scoped to the reporter's destination. Another client in
    the same process, talking to another URL, keeps its full log line."""
    reporter = _reporter(DESTINATIONS["slack path"], 200)
    other_url = "https://api.example.org/v1/items/42?page=3"
    other = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200)))
    try:
        with _RootCapture() as cap:
            other.get(other_url)
    finally:
        other.close()
        reporter.close()
    assert other_url in cap.text, cap.text


# ── sink 2: the reporter's own line ─────────────────────────────────────────

@pytest.mark.parametrize("shape", sorted(AWKWARD))
def test_reporter_line_does_not_carry_the_credential(shape):
    """Against a mock 500, so nothing here touches the network: the URL either
    fails to parse before the transport is reached (no scheme, bad port) or the
    request is answered with an error httpx puts the full URL into."""
    reporter = _reporter(AWKWARD[shape], 500)
    try:
        with _RootCapture() as cap:
            reporter.report([{"event": "test"}])
    finally:
        reporter.close()
    cap.assert_clean(f"WebhookReporter ({shape})")
    own = [ln for ln in cap.text.splitlines() if ln.startswith("xaidr.reporters")]
    assert own and "WebhookReporter failed" in own[0], (
        f"the reporter's failure line is gone:\n{cap.text}")


@pytest.mark.parametrize("shape", ["paren in the path", "quote in the path",
                                   "query past the regex bound"])
def test_reporter_line_still_names_the_host_and_status(shape):
    """Non-vacuity for the scrub: the failure is still diagnosable."""
    reporter = _reporter(AWKWARD[shape], 500)
    try:
        with _RootCapture() as cap:
            reporter.report([{"event": "test"}])
    finally:
        reporter.close()
    own = [ln for ln in cap.text.splitlines() if ln.startswith("xaidr.reporters")]
    assert own, f"the reporter's failure line is gone:\n{cap.text}"
    assert "collector.example.com" in own[0] and "500" in own[0], own[0]
