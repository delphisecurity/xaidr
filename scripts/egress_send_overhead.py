#!/usr/bin/env python3
"""What the egress seam adds to one client-level send, on httpx and on httpx2.

For each installed family (``httpx``, ``httpx2``) this times one ``client.post``
of a fixed, benign A2A-shaped JSON body through an in-process ``MockTransport``
(no socket, so the transport costs the same with and without the seam), in
three configurations on the same machine and in the same process:

  * ``plain``   — no ``protect()``: what the client costs on its own;
  * ``scanned`` — under ``protect()``, no S14 extension: the destination check,
    the scan of the request body and the scan of the response;
  * ``attested`` — under ``protect()`` with an S14 extension that returns one
    header: the scan, the body digest, the view and the header merge too.

The overhead of a configuration is its median minus ``plain``'s median. It
prints the machine, the versions, the body size, and median / p95 / p99 per
cell for every repeat; nothing is trimmed and nothing is asserted (exit 0
unless the run failed). The figures describe this machine, not yours: run it.

    python scripts/egress_send_overhead.py [--sends 2000] [--repeats 3]

Standard library, ``xaidr`` and the HTTP clients it wraps. No network.
"""
from __future__ import annotations

import argparse
import math
import os
import platform
import statistics
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from _provenance import bind  # noqa: E402

PROV = bind(__file__)

import xaidr  # noqa: E402
from xaidr import Sensor, SensorExtension  # noqa: E402

URL = "https://peer.example/agents/peer/x"
BODY = {"jsonrpc": "2.0", "id": "1", "method": "message/send",
        "params": {"message": {"role": "user", "parts": [
            {"kind": "text", "text": "Please summarise the attached quarterly figures "
                                     "for the planning meeting on Thursday."}]}}}
ANSWER = {"result": {"message": {"parts": [{"kind": "text", "text": "Here is the summary."}]}}}
WARMUP = 200


class _Null:
    def report(self, *a, **k):
        pass

    def close(self, *a, **k):
        pass


class _Attest(SensorExtension):
    name = "overhead-attest"

    def attest_egress(self, view):
        return {"x-delphi-attestation": "overhead"}


def _pct(samples, q):
    s = sorted(samples)
    return s[max(0, math.ceil(q * len(s)) - 1)]


def _time_posts(hx, sends):
    with hx.Client(transport=hx.MockTransport(lambda r: hx.Response(200, json=ANSWER))) as c:
        for _ in range(WARMUP):
            c.post(URL, json=BODY)
        out = []
        for _ in range(sends):
            t0 = time.perf_counter()
            c.post(URL, json=BODY)
            out.append((time.perf_counter() - t0) * 1000.0)
    return out


def _cell(hx, config, sends):
    if config == "plain":
        return _time_posts(hx, sends)
    ext = [_Attest()] if config == "attested" else []
    sensor = Sensor(agent_id="overhead", reporter=_Null(), extensions=ext)
    xaidr.protect(sensor=sensor, targets=[hx.__name__], quiet=True)
    try:
        return _time_posts(hx, sends)
    finally:
        xaidr.unprotect()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sends", type=int, default=2000)
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args()

    families = []
    for name in ("httpx", "httpx2"):
        try:
            families.append(__import__(name))
        except ImportError:
            print(f"{name:7s}: not installed, not measured")
    import json as _json
    body_bytes = len(_json.dumps(BODY, separators=(",", ":")).encode())
    print(f"platform : {platform.platform()}")
    print(f"python   : {platform.python_implementation()} {platform.python_version()}")
    print(f"cpu count: {os.cpu_count()}")
    for hx in families:
        print(f"{hx.__name__:9s}: {hx.__version__}")
    print(f"body     : {body_bytes} bytes of JSON; {args.sends} timed sends per cell after "
          f"{WARMUP} warmup, {args.repeats} repeats; MockTransport, no socket")
    print()
    print(f"{'family':7s} {'config':9s} {'rep':>3s} {'median ms':>10s} {'p95 ms':>8s} "
          f"{'p99 ms':>8s} {'overhead ms':>12s}")
    for rep in range(1, args.repeats + 1):
        for hx in families:
            plain = None
            for config in ("plain", "scanned", "attested"):
                samples = _cell(hx, config, args.sends)
                med = statistics.median(samples)
                if config == "plain":
                    plain = med
                over = med - plain
                print(f"{hx.__name__:7s} {config:9s} {rep:>3d} {med:>10.3f} "
                      f"{_pct(samples, 0.95):>8.3f} {_pct(samples, 0.99):>8.3f} "
                      f"{('-' if config == 'plain' else f'{over:+.3f}'):>12s}")
    print()
    print("overhead = the configuration's median minus plain's median, same family, same repeat")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
