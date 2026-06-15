"""reporters.py — Pluggable telemetry sinks (the emit-anywhere layer).

A Reporter receives batches of security events and sends them somewhere:
stdout, a file, a webhook, an OpenTelemetry pipeline, or (in the commercial
package) the Delphi Brain. The sensor's job is to SEE and EMIT; where events
go is the Reporter's job.

This is the decoupling seam: the open sensor ships with standalone reporters
(Stdout/File/Webhook/OTel) and never depends on any backend. The commercial
Brain reporter implements this same protocol in a separate package and plugs
in via one line — no sensor change, no reinstall.

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

    def __init__(self, stream: Any = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

    def report(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            try:
                self._stream.write(json.dumps(event, separators=(",", ":")) + "\n")
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

    def __init__(self, path: str) -> None:
        self._path = path
        self._fh = open(path, "a", encoding="utf-8")

    def report(self, events: list[dict[str, Any]]) -> None:
        try:
            for event in events:
                self._fh.write(json.dumps(event, separators=(",", ":")) + "\n")
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
    Requires httpx (already a sensor dependency).
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> None:
        import httpx  # lazy: only needed if this reporter is used

        self._url = url
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            headers={"Content-Type": "application/json", **(headers or {})},
        )

    def report(self, events: list[dict[str, Any]]) -> None:
        try:
            body = json.dumps({"events": events}, separators=(",", ":")).encode("utf-8")
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
        # Placeholder structured record. Replaced with full LogRecord +
        # gen_ai.security.* attribute mapping during the schema-emission phase.
        from opentelemetry._logs import LogRecord  # type: ignore

        return LogRecord(
            body=json.dumps(event, separators=(",", ":")),
            attributes={"event.domain": "agent.security"},
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

