"""The result reader records every key the argument reader reads.

A tool result that IS a value names every destination the same value names as an
argument: the whole-value reading (every reading of the authority split, the S-4
fallback key, mailbox lists, the scheme-less forms) and the atoms. Otherwise a
destination a result named could only ever read ``unresolved`` when a later
call sends to it. Checked over every vendored published vector
(``tests/published_vectors/vectors.jsonl``).
"""
from __future__ import annotations

import json
from pathlib import Path

from xaidr.value_origin._extract import extract_with_observed
from xaidr.value_origin._ledger import result_authorities

VECTORS = Path(__file__).resolve().parent / "published_vectors" / "vectors.jsonl"


def _arg_keys(v):
    found, _, observed = extract_with_observed({"v": v})
    return {f.destination.key() for f in found + observed if f.destination is not None}


def test_result_keys_contain_argument_keys_over_every_published_vector():
    values = sorted({json.loads(line)["v"] for line in VECTORS.open(encoding="utf-8")})
    assert len(values) > 15_000
    unrecorded = []
    for v in values:
        lost = _arg_keys(v) - {a.key() for a in result_authorities(v)}
        if lost:
            unrecorded.append((v, sorted(lost)))
    assert not unrecorded, (
        f"{len(unrecorded)} of {len(values)} published vectors name destinations as an "
        f"argument that a tool result of the same text does not record: {unrecorded[:10]}")


def test_a_host_utf46_refuses_is_recorded_from_a_result_with_its_fallback_key():
    from xaidr.value_origin import (bind_fresh_ledger, evaluate_call, record_tool_result,
                                    unbind_ledger)
    bind_fresh_ledger()
    record_tool_result("web_fetch", {}, "download from http://xn--0ca24w/", designations=(),
                       result_blocked=False)
    v = evaluate_call("http_get", {"url": "http://xn--0ca24w/"}, flow_active=True)
    unbind_ledger()
    assert v.wire.value == "untrusted_source", (
        f"a host the core keys by its S-4 fallback, named only by a tool result, read "
        f"{v.wire.value}")
