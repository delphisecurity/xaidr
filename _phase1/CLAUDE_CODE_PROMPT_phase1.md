# Claude Code Prompt — Phase 1: Pluggable Reporter (open-source sensor)

Run this in the NEW open-source repo (the vendor-neutral Apache-2.0 sensor),
working from a copy of the current SDK code.

GOAL: Decouple telemetry delivery from the Brain. Introduce a pluggable
Reporter interface so the sensor emits events to stdout/file/webhook/OTel by
default and depends on NO backend. This is the keystone of the open build.

KEY DIFFERENCE FROM THE PAID SDK: in THIS open repo, the default reporter is
StdoutReporter and there is NO Brain reporter. (The paid SDK keeps a
_BrainReporter; the open repo must not include it.)

---

## 1. NEW FILE: `xaidr/reporters.py`

Create it with the content of the attached `reporters.py`, with ONE change for
the open repo: **DELETE the `_BrainReporter` class entirely** (the block at the
bottom under "Commercial sink — NOT part of the open-source SDK"). The open repo
ships only: `Reporter` (protocol), `StdoutReporter`, `FileReporter`,
`WebhookReporter`, `OTelReporter`, `MultiReporter`.

Verify after: `python -c "import ast; ast.parse(open('xaidr/reporters.py').read())"`
and confirm `httpx` / `opentelemetry` are NOT imported at module top (they must
be lazy, inside the reporters that use them).

## 2. EDIT `xaidr/telemetry.py` — refactor `SyncTelemetryQueue`

Replace the Brain-coupled delivery with a pluggable reporter. Specifically:

- `__init__` signature becomes:
  `def __init__(self, reporter=None, batch_size=50, flush_interval_sec=5.0):`
  Remove `sentinel_url`, `api_key`, `identity`, and the `httpx.Client`.
  If `reporter is None`, default to StdoutReporter:
  ```python
  if reporter is None:
      from .reporters import StdoutReporter
      reporter = StdoutReporter()
  self._reporter = reporter
  ```
- `_flush(batch)` becomes:
  ```python
  def _flush(self, batch):
      try:
          self._reporter.report(batch)
          logger.debug("reported %d telemetry events", len(batch))
      except Exception as exc:
          logger.warning("reporter failed, dropping %d events: %s", len(batch), exc)
  ```
- `close_sync()`: replace `self._client.close()` with:
  ```python
  try:
      self._reporter.close()
  except Exception:
      pass
  ```
- Keep all the batching/threading machinery (start, enqueue, _run,
  _collect_batch) unchanged.
- Add under TYPE_CHECKING: `from .reporters import Reporter`.

NOTE on the async `TelemetryQueue` in the same file: the open sensor runs in
local mode and does not use it. Either apply the same reporter refactor to it
OR remove remote-mode/`TelemetryQueue` from the open repo. Recommend: remove
remote mode from the open sensor (it's a Brain-only path). Confirm with the
maintainer before deleting.

## 3. EDIT `xaidr/sensor.py`

- Add `from .reporters import Reporter` near the telemetry import.
- Add a `reporter: "Reporter" = None` parameter to `Sensor.__init__` (end of
  the signature).
- In the local-mode branch where `SyncTelemetryQueue` is constructed, replace
  the old `sentinel_url=/api_key=/identity=` construction with:
  ```python
  resolved_reporter = reporter
  if resolved_reporter is None:
      from .reporters import StdoutReporter
      resolved_reporter = StdoutReporter()
  self._telemetry = SyncTelemetryQueue(
      reporter=resolved_reporter,
      batch_size=telemetry_batch_size,
      flush_interval_sec=telemetry_flush_interval_sec,
  )
  ```
  (In the open repo the default is StdoutReporter — NOT a Brain reporter.)

## 4. VERIFY (must all pass before commit)

```python
# a) parses
python -c "import ast; [ast.parse(open(f).read()) for f in ['xaidr/reporters.py','xaidr/telemetry.py','xaidr/sensor.py']]; print('parse ok')"

# b) reporters work standalone
python - <<'PY'
from xaidr.reporters import StdoutReporter, FileReporter, MultiReporter, Reporter
import io, json
buf = io.StringIO(); sr = StdoutReporter(stream=buf)
sr.report([{'a':1}]); assert json.loads(buf.getvalue().strip())=={'a':1}
assert isinstance(StdoutReporter(), Reporter)
print('reporters ok')
PY

# c) telemetry routes through reporter, standalone default, fail-open
python - <<'PY'
from xaidr.telemetry import SyncTelemetryQueue
cap=[]
class C:
    def report(self,e): cap.extend(e)
    def close(self): pass
q=SyncTelemetryQueue(reporter=C(), flush_interval_sec=0.2)
q.enqueue({'x':1}); import time; time.sleep(0.4); q.close_sync()
assert cap==[{'x':1}]
SyncTelemetryQueue()  # zero-arg standalone default must work
print('telemetry ok')
PY

# d) end-to-end: Sensor scan emits through a reporter, detection intact
#    (benign -> allowed, attack -> blocked, event captured)
```

DO NOT:
- Include `_BrainReporter` in the open repo.
- Default to any Brain URL or require an api_key for telemetry.
- Import httpx/opentelemetry at module top in reporters.py.
- Change the batching/threading logic.

Commit message: `feat(reporters): pluggable telemetry sink, decouple from backend`
Do not push to PyPI.
