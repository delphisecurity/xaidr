"""reporters.py — Pluggable telemetry sinks (the emit-anywhere layer).

A Reporter receives batches of security events and sends them somewhere:
stdout, a file, a webhook, or an OpenTelemetry pipeline. The sensor's job is to
SEE and EMIT; where events go is the Reporter's job.

This is the decoupling seam: the sensor ships with standalone reporters
(Stdout/File/Webhook/OTel) and never depends on any backend. Any custom sink
that implements this same protocol plugs in via one line — no sensor change,
no reinstall.

Contract:
    report(events: list[dict]) -> None    # emit a batch; SHOULD fail open
    close() -> None                        # flush/cleanup on shutdown

report() is synchronous. The async telemetry queue bridges to it via a thread
executor so a reporter doing blocking I/O never stalls an event loop.
Reporters MUST fail open: an exception in report() is caught by the queue and
the scan path is never affected.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger("xaidr.reporters")


# ── CREDENTIALS MUST NOT REACH THE LOGS ──────────────────────────────────────
# A webhook destination is user-supplied and routinely carries its own
# authentication in the URL: `?token=...`, `?api_key=...`, or `user:pass@host`.
# On a delivery failure this module logged the destination and the exception,
# and the credential appeared in BOTH. That is worth spelling out because it is
# the thing that made the first fix incomplete: the URL and the exception are
# SEPARATE SINKS. httpx puts the full request URL inside the text of
# HTTPStatusError ("Server error '500 ...' for url '<url>'"), so redacting
# `self._url` and interpolating `exc` still emits the secret, once instead of
# twice. Measured on 1.12.0 with a canary in the query: two occurrences on one
# line, and two again with the credential in userinfo.
#
# The logs are the wrong place for this to land. They are the artefact most
# likely to be shipped to a third party, retained longest, and read by the
# widest audience, and a reporter failure is exactly when an operator pastes one
# into a ticket.
#
# THE PATH IS ALSO A CREDENTIAL SINK, and the first fix missed it. Query values
# and userinfo are where a credential goes when the URL is an API endpoint; they
# are NOT where it goes on the destinations this reporter is actually pointed at.
# The three most common webhook sinks carry the whole secret in the PATH:
#
#   Slack     https://hooks.slack.com/services/T0A1B2C3/B9Z8Y7X6/<token>
#   Discord   https://discord.com/api/webhooks/<id>/<token>
#   Teams     https://<org>.webhook.office.com/webhookb2/<guid>@<guid>/IncomingWebhook/<guid>/<guid>
#
# Measured on published 1.13.0 and 1.14.0 and on the 1.15.0 candidate: a Slack
# webhook URL put the token on the log line FOUR times (the reporter's own line
# and httpx's exception text, each seen by the handler and again on stderr).
#
# WHAT IS KEPT, AND THE ARGUMENT FOR IT.
#
#   scheme, host, port   KEPT. This is what "the destination is still named"
#                        means: an operator can tell a failing Slack webhook from
#                        a failing internal collector. A hostname is not a
#                        secret; it is the thing you need to fix the outage.
#   query KEYS           KEPT, as before. `token=<redacted>` says the call
#                        carried a token without saying which.
#   path SEGMENT COUNT   KEPT. It distinguishes two endpoints on one host, and a
#                        count carries no content.
#   path segment TEXT    REMOVED, every segment, including the first.
#   userinfo, query
#     VALUES, fragment   REMOVED, as before.
#
# WHY EVERY SEGMENT AND NOT A CLEVERER RULE. There is no positional rule: Slack's
# secret is the last three taken together, Discord's is the last, Teams' is
# spread across four, and some services put the token in the FIRST segment
# (`https://host/<token>`). There is no shape rule either that is not entropy
# guessing, and entropy guessing fails open on a short token and fails closed on
# a hashed route id — so it would hand back the exact bug this comment describes,
# with a heuristic in front of it. `redact_url`'s own contract already says "we
# could not parse it" must not become "so we printed it"; the same reasoning says
# "we could not tell whether this segment is a secret" must not become "so we
# printed it". Fail closed on the whole path.
#
# THE COST IS REAL AND IT IS ACCEPTED: a log line no longer says WHICH route on a
# host failed, only that a 3-segment one did. Weighed against a credential in a
# ticket, that is the correct trade, and the reporter class name plus the host
# already narrow a failure to one configured destination in every shipped setup.

_URL_IN_TEXT_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]{0,15}://[^\s'\"<>)\]}]{0,2000}")

_REDACTED = "<redacted>"


def _redact_path(path: str) -> str:
    """Every path segment replaced, the SHAPE of the path kept.

    ``/services/T0A1B2C3/B9Z8Y7X6/xoxb-secret`` becomes
    ``/<redacted>/<redacted>/<redacted>/<redacted>``: four segments, no content.
    A leading slash and a trailing slash are preserved because they are
    structure; an empty path stays empty and ``/`` stays ``/``.

    See the module comment for why no segment survives, not even the first.
    """
    if not path or path == "/":
        return path
    trailing = path.endswith("/")
    segments = [s for s in path.split("/") if s]
    if not segments:
        return path
    out = "/" + "/".join(_REDACTED for _ in segments)
    return out + "/" if trailing else out


def redact_url(url: Any) -> str:
    """A URL safe to log: the destination named, every secret-bearing part gone.

    Keeps what an operator needs to identify the destination (scheme, host, port,
    and the NUMBER of path segments) and removes what only an attacker benefits
    from (userinfo, path segment text, query VALUES, fragment). Query KEYS are
    kept: knowing the call carried a `token` parameter is diagnostic, knowing its
    value is a leak.

    The path is redacted in full. The canonical WebhookReporter destinations —
    Slack, Discord, Teams — carry the entire secret in path segments, and there
    is no positional or shape rule that separates a route segment from a token
    without guessing. See the module comment.

    Never raises. A value that cannot be parsed is reported as unloggable rather
    than passed through, because "we could not parse it" must not become "so we
    printed it".
    """
    try:
        text = url if isinstance(url, str) else str(url)
        parts = urlsplit(text)
        if not parts.scheme and not parts.netloc:
            return text                      # not a URL; nothing to redact
        netloc = parts.netloc
        if "@" in netloc:                    # strip userinfo entirely
            netloc = f"{_REDACTED}@{netloc.rsplit('@', 1)[1]}"
        query = parts.query
        if query:
            out = []
            for pair in query.split("&"):
                if not pair:
                    continue
                key = pair.split("=", 1)[0]
                out.append(f"{key}={_REDACTED}" if "=" in pair else pair)
            query = "&".join(out)
        fragment = _REDACTED if parts.fragment else ""
        return urlunsplit(
            (parts.scheme, netloc, _redact_path(parts.path), query, fragment))
    except Exception:
        return "<unloggable-url>"


def redact_text(value: Any) -> str:
    """Exception text with every URL inside it redacted.

    The second sink. Applied to anything derived from an exception before it is
    interpolated into a log record, because the libraries we call put the
    request URL into their own error strings and we do not control that.

    The pattern is bounded and has no nested quantifier, per the ReDoS
    invariants this project holds for anything that runs on attacker-influenced
    text.
    """
    try:
        text = value if isinstance(value, str) else str(value)
        return _URL_IN_TEXT_RE.sub(lambda m: redact_url(m.group(0)), text)
    except Exception:
        return "<unloggable>"


def safe_exc(exc: BaseException) -> str:
    """What to log for an exception: its type and its redacted message."""
    try:
        return f"{type(exc).__name__}: {redact_text(exc)}"
    except Exception:
        return "<unloggable-exception>"


def _apply_schema(event, schema):
    """Optionally map an internal event to the OpenA2A gen_ai.security.* shape."""
    if schema == "openA2A":
        from .schema import to_openA2A
        return to_openA2A(event)
    return event


def apply_default_schema(reporter: Any, schema: str | None) -> None:
    """Propagate a default output ``schema`` into a reporter that lacks one.

    Precedence: a reporter's OWN explicit schema always wins — this only FILLS
    reporters whose schema is unset (``_schema is None``). So ``Sensor(schema=)``
    is the default applied to every reporter that didn't choose its own, and a
    reporter constructed as ``FileReporter(path, schema="openA2A")`` keeps its
    choice even if the sensor's default differs. Nothing is ever silently
    dropped: the schema reaches the path deployments actually use (their own
    reporter), not just the auto-created one.

    Recurses into ``MultiReporter`` children. Reporters that carry no ``_schema``
    attribute (e.g. ``OTelReporter``, which always emits openA2A, or a fully
    custom sink) are left untouched — there is nothing to fill.
    """
    if schema is None:
        return
    children = getattr(reporter, "_reporters", None)
    if isinstance(children, list):
        for child in children:
            apply_default_schema(child, schema)
        return
    if hasattr(reporter, "_schema") and getattr(reporter, "_schema") is None:
        reporter._schema = schema


@runtime_checkable
class Reporter(Protocol):
    """The pluggable telemetry sink contract.

    Implement this to send security events anywhere. Keep report() resilient:
    raising is tolerated (the queue fails open) but swallowing/logging your own
    errors is preferred so batches aren't silently lost on transient issues.
    """

    def report(self, events: list[dict[str, Any]]) -> None:
        """Emit a batch of events. Called from a background thread."""
        ...

    def close(self) -> None:
        """Flush and release resources on shutdown."""
        ...


class StdoutReporter:
    """Default standalone reporter — writes each event as one JSON line to stdout.

    Zero config, no dependencies, no network. This is the out-of-the-box sink
    so the sensor is useful immediately with no account and no backend.
    """

    def __init__(self, stream: Any = None, schema: str | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self._schema = schema

    def report(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            try:
                payload = _apply_schema(event, self._schema)
                self._stream.write(json.dumps(payload, separators=(",", ":")) + "\n")
            except Exception as exc:  # never break the batch
                logger.warning("StdoutReporter failed to write event: %s", safe_exc(exc))
        try:
            self._stream.flush()
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._stream.flush()
        except Exception:
            pass


class FileReporter:
    """Appends events as JSON lines (JSONL) to a file.

    Suitable for local audit, log shipping, or pickup by a SIEM agent tailing
    the file. Opens in append mode; one event per line.
    """

    def __init__(self, path: str, schema: str | None = None) -> None:
        self._path = path
        self._fh = open(path, "a", encoding="utf-8")
        self._schema = schema

    def report(self, events: list[dict[str, Any]]) -> None:
        try:
            for event in events:
                payload = _apply_schema(event, self._schema)
                self._fh.write(json.dumps(payload, separators=(",", ":")) + "\n")
            self._fh.flush()
        except Exception as exc:
            logger.warning("FileReporter failed (%s): %s", redact_url(self._path), safe_exc(exc))

    def close(self) -> None:
        try:
            self._fh.flush()
            self._fh.close()
        except Exception:
            pass


class WebhookReporter:
    """POSTs each batch as JSON to a user-controlled URL (SIEM, collector, etc.).

    The destination is entirely the user's: their SIEM ingest endpoint, an
    OTel collector's HTTP receiver, an internal service. Delphi is not involved.

    Requires httpx, which is NOT part of the zero-dependency base install.
    Install the ``http`` extra::

        pip install xaidr[http]

    Constructing a WebhookReporter without httpx raises a clear ImportError
    naming that fix (rather than a bare ``No module named 'httpx'``).
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        schema: str | None = None,
    ) -> None:
        try:
            import httpx  # lazy: only needed if this reporter is used
        except ImportError as exc:
            raise ImportError(
                "WebhookReporter requires httpx, which is not a base dependency. "
                "Install with:  pip install xaidr[http]"
            ) from exc

        self._url = url
        self._schema = schema
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        # Exempt this client from xaidr.protect()'s egress patch. Without it,
        # once httpx.Client.send is patched, THIS POST gets scanned, that scan
        # enqueues an event, that event is flushed as another POST, and the
        # sensor talks to itself for as long as the process lives. Set as a
        # plain attribute rather than importing the autopatch package, so
        # reporters.py stays free of that dependency edge.
        try:
            self._client._xaidr_exempt = True
        except Exception:  # pragma: no cover — httpx.Client accepts attributes
            pass

    def report(self, events: list[dict[str, Any]]) -> None:
        try:
            payload = [_apply_schema(e, self._schema) for e in events]
            body = json.dumps({"events": payload}, separators=(",", ":")).encode("utf-8")
            resp = self._client.post(self._url, content=body)
            resp.raise_for_status()
        except Exception as exc:
            # BOTH arguments are sanitised. The URL because the destination
            # carries the credential, and the exception because httpx repeats
            # the full URL inside its own message.
            logger.warning(
                "WebhookReporter failed to deliver %d events to %s: %s",
                len(events), redact_url(self._url), safe_exc(exc),
            )

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass


class OTelReporter:
    """Emits events through the OpenTelemetry logging bridge.

    Each security event becomes an OTel log record so it flows into any
    OTel-compatible backend (collector, Datadog, Honeycomb, etc.) alongside
    existing agent observability. Schema-attribute mapping to gen_ai.security.*
    is applied in the schema-emission phase; here we attach the event payload
    so it rides the OTel pipeline today. Requires the opentelemetry-api/sdk
    extras (optional).
    """

    def __init__(self, logger_name: str = "xaidr.security") -> None:
        try:
            from opentelemetry import _logs as otel_logs  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dep guidance
            raise ImportError(
                "OTelReporter requires the optional 'otel' extra. "
                "Install with:  pip install xaidr[otel]"
            ) from exc
        self._otel_logs = otel_logs
        self._logger_name = logger_name

    def report(self, events: list[dict[str, Any]]) -> None:
        try:
            otel_logger = self._otel_logs.get_logger(self._logger_name)
        except Exception as exc:
            logger.warning("OTelReporter could not get OTel logger: %s", safe_exc(exc))
            return
        for event in events:
            try:
                # Emit as a structured log record; attribute mapping to
                # gen_ai.security.* is layered in the schema-emission phase.
                otel_logger.emit(  # type: ignore[attr-defined]
                    self._build_record(event)
                )
            except Exception as exc:
                logger.warning("OTelReporter failed to emit event: %s", safe_exc(exc))

    def _build_record(self, event: dict[str, Any]) -> Any:
        # The OTel reporter's natural output IS the OpenA2A schema: map the
        # internal event to gen_ai.security.* and place those flat, dotted keys
        # directly as the log record attributes.
        from opentelemetry._logs import LogRecord  # type: ignore

        from .schema import to_openA2A

        attributes = to_openA2A(event)
        attributes["event.domain"] = "agent.security"
        return LogRecord(
            body=json.dumps(event, separators=(",", ":")),
            attributes=attributes,
        )

    def close(self) -> None:
        pass


class MultiReporter:
    """Fans a batch out to several reporters. Each is isolated: one failing
    reporter does not stop the others."""

    def __init__(self, *reporters: Reporter) -> None:
        self._reporters = list(reporters)

    def report(self, events: list[dict[str, Any]]) -> None:
        for r in self._reporters:
            try:
                r.report(events)
            except Exception as exc:
                logger.warning("reporter %s failed: %s", type(r).__name__, safe_exc(exc))

    def close(self) -> None:
        for r in self._reporters:
            try:
                r.close()
            except Exception:
                pass

