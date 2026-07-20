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
import sys
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("xaidr.reporters")


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
                logger.warning("StdoutReporter failed to write event: %s", exc)
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
            logger.warning("FileReporter failed (%s): %s", self._path, exc)

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

    def report(self, events: list[dict[str, Any]]) -> None:
        try:
            payload = [_apply_schema(e, self._schema) for e in events]
            body = json.dumps({"events": payload}, separators=(",", ":")).encode("utf-8")
            resp = self._client.post(self._url, content=body)
            resp.raise_for_status()
        except Exception as exc:
            logger.warning(
                "WebhookReporter failed to deliver %d events to %s: %s",
                len(events), self._url, exc,
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
            logger.warning("OTelReporter could not get OTel logger: %s", exc)
            return
        for event in events:
            try:
                # Emit as a structured log record; attribute mapping to
                # gen_ai.security.* is layered in the schema-emission phase.
                otel_logger.emit(  # type: ignore[attr-defined]
                    self._build_record(event)
                )
            except Exception as exc:
                logger.warning("OTelReporter failed to emit event: %s", exc)

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
                logger.warning("reporter %r failed: %s", r, exc)

    def close(self) -> None:
        for r in self._reporters:
            try:
                r.close()
            except Exception:
                pass

