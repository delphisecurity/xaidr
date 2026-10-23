"""UTS-46 conformance: IdnaTestV2 of the Unicode version the core pins, every row.

The core's ToASCII (``xaidr.value_origin._idna``) is UTS-46 nontransitional on
the vendored Unicode 13.0 data. IdnaTestV2 13.0.0 is vendored in
``tests/published_vectors/idna-13.0.0.jsonl`` (extracted by
``scripts/published_vectors.py``; its source and sha256 are in SOURCES.json).
That file is computed with UseSTD3ASCIIRules, CheckHyphens, CheckBidi,
CheckJoiners and VerifyDnsLength all on (13.0 reports a STD3 failure as P1 or
V6; U1 arrived in 15.1), so it is checked with ``strict=True``, which turns on
the three the core leaves off (S-4): a row with no status code encodes to its
toAsciiN, and a row with any code fails. A name valid under every check is
valid under fewer, so each such row also encodes the same with the core's own
flags.
"""
from __future__ import annotations

import json
from pathlib import Path

from xaidr.value_origin import _idna_data
from xaidr.value_origin._idna import to_ascii

ROWS = Path(__file__).resolve().parents[1] / "published_vectors" / "idna-13.0.0.jsonl"


def _rows():
    return [json.loads(line) for line in ROWS.open(encoding="utf-8")]


def test_the_pinned_version_is_the_vendored_tables():
    assert _idna_data.UNICODE_VERSION == "13.0.0"
    assert len(_rows()) == 6225


def test_every_idnatestv2_13_row_with_the_files_own_flags():
    wrong = []
    for r in _rows():
        want = None if r["status"] else r["to_ascii_n"]
        got = to_ascii(r["source"], strict=True)
        if got != want:
            wrong.append((r["source"], want, got, r["status"]))
    assert not wrong, (f"{len(wrong)} of 6225 IdnaTestV2 13.0.0 rows read otherwise "
                       f"(source, expected, got, status): {wrong[:12]}")


def test_every_valid_row_encodes_the_same_with_the_cores_flags():
    wrong = [(r["source"], r["to_ascii_n"], to_ascii(r["source"])) for r in _rows()
             if not r["status"] and to_ascii(r["source"]) != r["to_ascii_n"]]
    assert not wrong, f"{len(wrong)} valid rows encode otherwise with S-4's flags: {wrong[:12]}"
