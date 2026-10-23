"""The core reads every published vector the same on every interpreter and OS (V-4).

    python scripts/published_agreement.py CORE.json [CORE.json ...]

Each file is ``scripts/published_differential.py --core-out`` from one CI cell (an
OS and an interpreter): for every vector, and for generated values over code
points Unicode 13.0 leaves unassigned, the core's findings in order (parse
failures included) and the wire and ENFORCE decision of a call carrying it with an
empty ledger, after the principal wrote it, after a tool result was it and after a
tool result named it in a sentence. The wire must be identical, not only the
decision. Any vector two cells read differently is printed, and the run exits 1.
Fewer than two files is a refusal, never a pass.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv=None) -> int:
    paths = [Path(p) for p in (sys.argv[1:] if argv is None else argv)]
    if len(paths) < 2:
        print(f"REFUSING: {len(paths)} core reading file(s); agreement needs two or more")
        return 2
    cores = {str(p): json.loads(p.read_text()) for p in paths}
    names = sorted(cores)
    base = cores[names[0]]
    bad = 0
    for n in names[1:]:
        other = cores[n]
        if set(other) != set(base):
            print(f"{n}: a different vector set than {names[0]}")
            bad += 1
            continue
        diff = [v for v in base if base[v] != other[v]]
        bad += len(diff)
        for v in diff[:20]:
            print(f"DIFFERS {ascii(v)[:80]}: {names[0]} {base[v]} | {n} {other[v]}")
        print(f"{n}: {len(diff)} of {len(base)} vectors read otherwise than {names[0]}")
    print("AGREEMENT: " + ("RED" if bad else f"clean across {len(names)} cells"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
