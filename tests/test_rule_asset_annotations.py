"""No rule asset may carry an annotation field, because every one reaches a package.

THE DEFECT. The rule JSONs under ``xaidr/rules/`` carried free-text notes in
underscore-prefixed keys beside the fields the loader reads. The loader ignores
those keys, so nothing at runtime depended on them, and nobody reviewed them as
prose either: they were edited as data and shipped verbatim in every wheel.

WHY THIS IS KEY-SHAPED AND NOT A CHECK FOR ONE FIELD NAME. Rewording individual
notes leaves the field legal, so the next rule edit writes new ones. A check for
one literal key would repeat that with the next name someone picks. The rule is
therefore structural: a key starting with ``_`` anywhere in any rule asset
fails, at any depth, whatever it is called.

WHERE THE NOTE GOES INSTEAD. The commit message or the PR body. Git keeps it,
and the wheel does not.

The failure message names the file, the JSON path and the key. It never prints
the value: CI logs on a public repository are public, and printing the text this
gate exists to keep out of the package would publish it somewhere else.
"""
from __future__ import annotations

import json
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent / "xaidr" / "rules"


def _underscore_keys(node, path="$"):
    """Yield the JSON path of every ``_``-prefixed key, at any depth."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}"
            if key.startswith("_"):
                yield here
            yield from _underscore_keys(value, here)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _underscore_keys(value, f"{path}[{i}]")


def test_the_walker_reaches_a_key_nested_in_lists_and_objects():
    """Non-vacuity for the gate below: a walker that never descends finds nothing
    and reports clean. The rule files nest rules in lists and steps in rules."""
    tree = [{"id": "r", "steps": [{"x": 1}, {"y": {"_deep": 1}}]}, {"_top": 1}]
    assert list(_underscore_keys(tree)) == ["$[0].steps[1].y._deep", "$[1]._top"]


def test_annotation_fields_must_not_reach_a_package():
    assets = sorted(RULES_DIR.rglob("*.json"))
    assert assets, (
        f"no JSON found under {RULES_DIR}. An empty set has no annotation fields "
        "and would pass, so this is a failure, not a pass.")

    found = []
    for asset in assets:
        with asset.open(encoding="utf-8") as fh:
            data = json.load(fh)
        rel = asset.relative_to(RULES_DIR.parent.parent)
        found.extend(f"{rel}: {p}" for p in _underscore_keys(data))

    assert not found, (
        f"annotation fields must not reach a package: {len(found)} "
        "underscore-prefixed key(s) in the rule assets, and every file under "
        "xaidr/rules/ ships verbatim in the wheel.\n  " + "\n  ".join(found) + "\n"
        "Nothing at runtime reads these keys. Delete them, and put the note in "
        "the commit message or the PR body, where git keeps it and the wheel "
        "does not.")
