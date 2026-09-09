"""The gate that matters most: seams registered nowhere change nothing.

Non-negotiable 1 of the enterprise-seam design. Every other test in the seam
suite proves an extension CAN change a verdict; this one proves that the case
shipping to every open user — no extensions — is byte-identical to the sensor
that existed before the seams did.

WHY THE COMPARISON IS WITHIN A SINGLE RUN rather than against a committed
digest. A pinned hash of "what main returned in September" rots the moment a
rule is legitimately retuned, and a rotting gate gets deleted or, worse,
regenerated without being read. Comparing a bare sensor against one carrying a
no-op extension asks the question that actually matters — does ATTACHING an
extension move anything — and it keeps asking it correctly for the life of the
codebase.

The digest over the whole committed corpus is still the unit of comparison, so
a seam that moved one verdict in 456 fails here rather than passing on a
spot-check of five inputs.
"""

import hashlib
import json
import os

from xaidr import Sensor, SensorExtension

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "shell_corpus.json")
BUCKETS = ("attacks", "benign", "benign_prose", "benign_templates")


class _NullReporter:
    def report(self, *a, **k): pass
    def close(self, *a, **k): pass


class _NoOp(SensorExtension):
    """Overrides nothing. The base class must be inert on every hook."""

    name = "noop"


class _Declining(SensorExtension):
    """Overrides the two wired hooks and declines on both."""

    name = "declining"

    def gate(self, req):
        return None

    def transform_verdict(self, req, result):
        return result


def _corpus_texts():
    with open(FIXTURE, encoding="utf-8") as fh:
        corpus = json.load(fh)
    out = []
    for bucket in BUCKETS:
        for i, entry in enumerate(corpus[bucket]):
            for key in ("command", "text", "template"):
                if key in entry:
                    out.append((bucket, i, entry[key]))
                    break
            else:  # pragma: no cover - fixture shape guard
                raise KeyError(f"{bucket}[{i}] has no text field: {list(entry)}")
    return out


def _digest(extensions):
    sensor = Sensor(agent_id="seam-oracle", enforcement_mode="block",
                    reporter=_NullReporter(), extensions=extensions)
    lines = []
    for bucket, i, text in _corpus_texts():
        r = sensor.scan(text, direction="input")
        rules = ",".join(sorted(r.rules or []))
        lines.append(f"{bucket}[{i:03d}] {r.action} {float(r.score):.4f} "
                     f"{r.category or '-'} {rules or '-'}")
    body = "\n".join(lines)
    return hashlib.sha256(body.encode("utf-8")).hexdigest(), len(lines)


def test_the_corpus_is_the_size_the_design_doc_claims():
    """Guards the denominator. A gate over an empty set passes vacuously."""
    assert len(_corpus_texts()) == 456


def test_a_noop_extension_moves_no_verdict_score_or_rule():
    bare, n_bare = _digest(())
    noop, n_noop = _digest([_NoOp()])
    assert n_bare == n_noop == 456
    assert bare == noop, (
        "attaching a no-op extension changed a verdict, score or rule set "
        "somewhere in the 456-row corpus"
    )


def test_an_extension_that_declines_on_every_wired_hook_moves_nothing():
    bare, _ = _digest(())
    declining, _ = _digest([_Declining()])
    assert bare == declining


def test_three_stacked_no_op_extensions_still_move_nothing():
    """Chain-walking order must not perturb anything when every link declines."""
    bare, _ = _digest(())
    stacked, _ = _digest([_NoOp(), _Declining(), _NoOp()])
    assert bare == stacked
