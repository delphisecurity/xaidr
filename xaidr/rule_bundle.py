"""Rule bundles: a complete rule set, adopted whole or not at all.

The sensor ships seven rule files inside the wheel (``xaidr/rules/*.json``) and
reads them at import. A bundle is the same seven files, as parsed JSON, under
one integer ``version``::

    {"version": 7, "files": {"all-l1-rules.json": [...], "output-l1-rules.json": [...],
                             "dangerous-intents.json": [...], "composite-rules.json": [...],
                             "attack-chains.json": [...], "typo-keywords.json": {...},
                             "impact-classes.json": {...}}}

``install`` stages every file through the same compile step the import uses,
in a STRICT mode where a rule that would be dropped (a pattern that does not
compile, a shape that is not the file's) refuses the whole bundle; only when
all seven stage does it swap all seven, under one lock. A refused bundle leaves
every rule file as it was. While a bundle is in force its ``version`` rides
every event as ``bundleVersion``; with none the key is absent.

The tables are the modules' own (``scanner.l1.INPUT_RULES`` and the others,
and the normaliser in force, ``scanner.normalizer.current()``), read by the
detectors at call time, so a bundle is in force for every sensor in the
process from the next scan each starts, whether the sensor was built before or
after the install. A scan in flight when the swap lands may read one layer's
old table and the next layer's new one; the seven assignments are one lock
away from being a single step, and that is where the line is drawn.

Open is unsigned: it never fetches a bundle and never verifies one. Signature
checking is the overlay's, which hands a verified bundle through S15
``SensorExtension.rule_bundle()`` at attach, or calls ``load_rule_bundle``.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Mapping, Optional

from .authz import classifier as _classifier
from .scanner import l1 as _l1
from .scanner import l2 as _l2
from .scanner import normalizer as _normalizer

__all__ = ["FILES", "BundleError", "validate", "install", "version", "packaged"]

#: The seven rule files a bundle must carry, every one of them.
FILES = (
    "all-l1-rules.json",
    "output-l1-rules.json",
    "dangerous-intents.json",
    "composite-rules.json",
    "attack-chains.json",
    "typo-keywords.json",
    "impact-classes.json",
)

_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
_LOCK = threading.Lock()
_VERSION: Optional[int] = None


class BundleError(ValueError):
    """The bundle is not a complete, well-formed rule set. The message names the
    file and the shape, never a rule's text."""


def version() -> Optional[int]:
    """The version of the bundle in force, or None when the packaged rules are."""
    return _VERSION


def _check_list(raw, filename: str) -> list:
    if not isinstance(raw, list) or not all(isinstance(e, dict) for e in raw):
        raise BundleError(f"{filename}: not a list of objects")
    return list(raw)


def _check_typo(raw) -> dict:
    """The typo file is staged the way it is used: a normaliser is BUILT from
    it. A table a normaliser cannot be built from refuses the bundle."""
    if not isinstance(raw, dict):
        raise BundleError("typo-keywords.json: not an object")
    for key in ("all_keywords", "denylist"):
        if key in raw and not isinstance(raw[key], list):
            raise BundleError(f"typo-keywords.json: {key} is not a list")
    for key in ("min_token_length", "max_edit_distance"):
        if key in raw and (isinstance(raw[key], bool) or not isinstance(raw[key], int)):
            raise BundleError(f"typo-keywords.json: {key} is not an integer")
    # Built AND run once on a short plain sentence: a table whose entries build
    # but do not normalise is refused here, not at a host's first scan.
    _normalizer.TypoNormalizer(config=dict(raw)).normalize("a short plain sentence to check")
    return dict(raw)


def validate(bundle) -> tuple:
    """Stage a bundle. Returns ``(version, staged)``, where ``staged`` maps each
    file name to its compiled table, or raises ``BundleError``. Nothing is
    installed."""
    if not isinstance(bundle, Mapping):
        raise BundleError("a bundle is a mapping with 'version' and 'files'")
    ver = bundle.get("version")
    if isinstance(ver, bool) or not isinstance(ver, int) or ver < 1:
        raise BundleError("version: not a positive integer")
    files = bundle.get("files")
    if not isinstance(files, Mapping):
        raise BundleError("files: not a mapping")
    missing = [f for f in FILES if f not in files or files[f] is None]
    extra = [f for f in files if f not in FILES]
    if missing or extra:
        raise BundleError(
            f"files: {len(missing)} of {len(FILES)} rule files absent or null, "
            f"{len(extra)} unknown")
    staged = {}
    try:
        staged["all-l1-rules.json"] = _l1._detectors_first(
            _l1._compile_rules(files["all-l1-rules.json"], "all-l1-rules.json", strict=True))
        staged["output-l1-rules.json"] = _l1._detectors_first(
            _l1._compile_rules(files["output-l1-rules.json"], "output-l1-rules.json", strict=True))
        staged["dangerous-intents.json"] = _l2._compile_intents(
            files["dangerous-intents.json"], strict=True)
        staged["composite-rules.json"] = _check_list(files["composite-rules.json"],
                                                     "composite-rules.json")
        staged["attack-chains.json"] = _check_list(files["attack-chains.json"], "attack-chains.json")
        staged["typo-keywords.json"] = _check_typo(files["typo-keywords.json"])
        staged["impact-classes.json"] = _classifier._build_ruleset(
            files["impact-classes.json"], strict=True)
    except BundleError:
        raise
    except Exception as exc:
        # The compile step names the file in its own message; the type is what
        # the caller logs. No rule text travels.
        raise BundleError(f"a rule file does not compile ({type(exc).__name__})") from exc
    return ver, staged


def install(bundle) -> bool:
    """Adopt ``bundle`` whole, or nothing. Returns True when the seven tables
    were swapped and the version is in force; False when the bundle was refused
    and every table is as it was. Never raises."""
    try:
        ver, staged = validate(bundle)
    except Exception:
        return False
    _swap(staged, ver)
    return True


def _swap(staged: dict, ver: Optional[int]) -> None:
    global _VERSION
    with _LOCK:
        _l1.INPUT_RULES = staged["all-l1-rules.json"]
        _l1.OUTPUT_RULES = staged["output-l1-rules.json"]
        _l2.INTENTS = staged["dangerous-intents.json"]
        _l2.COMPOSITES = staged["composite-rules.json"]
        _l2.CHAINS = staged["attack-chains.json"]
        _normalizer._TYPO_CONFIG = staged["typo-keywords.json"]
        # The normaliser in force, built from the STAGED table (it built once
        # already, in validate), so every scanner reads it from its next scan.
        _normalizer.set_current(_normalizer.TypoNormalizer(config=staged["typo-keywords.json"]))
        _classifier._RULESET = staged["impact-classes.json"]
        _VERSION = ver


def packaged(ver: int = 1) -> dict:
    """The seven packaged rule files, as a bundle under ``ver``. For a sensor
    this is a bundle equal to the rules it already runs."""
    files = {}
    for name in FILES:
        with open(os.path.join(_RULES_DIR, name), encoding="utf-8") as fh:
            files[name] = json.load(fh)
    return {"version": ver, "files": files}


def _reset() -> None:
    """Put the packaged rules back with no version in force. For tests."""
    _, staged = validate(packaged(1))
    _swap(staged, None)
