#!/usr/bin/env python3
"""Intentional-detection metrics: one catch rate, over the attacks we intend to catch.

    python scripts/intent_metrics.py                 # rules only
    python scripts/intent_metrics.py --nano          # + the opt-in ML signal
    python scripts/intent_metrics.py --nano --real-benign   # + the published FP figure

WHY THIS SCRIPT EXISTS, AND WHAT IT REPLACES
────────────────────────────────────────────
The figure this project published for years was `blocked / all attacks` — 165 of
281, 59% — presented as detection. That figure counts as a failure every entry
the ruleset deliberately declines to block. `terraform destroy` is not a missed
detection. It is the documented inverse of `terraform apply`, an ephemeral-
environment pipeline runs it on a schedule, and the shipped rule names the impact
class and hands the decision to a policy the deployer writes. Scoring that as a
miss was wrong from the start: it made the ruleset look weaker than it is in
exactly the place where it is behaving as designed, and it invited the reader to
"fix" the design by adding blocks that would break ordinary teardown pipelines.

Two changes, and the second is the one that matters:

  1. A CATCH is `blocked` OR `flagged`. A flag is a real detection: the event is
     emitted, scored and logged, and a deployer sees it. Counting only blocks
     confuses "we saw it" with "we stopped it".

  2. The DENOMINATOR is the attacks we intend to catch — every corpus attack
     minus the ones marked INTENDED in the fixture. That mark is a judgement,
     one entry at a time, written into tests/fixtures/shell_corpus.json next to
     the command it describes, with a reason. It is not computed here and it
     cannot be: no measurement can tell you what you meant to do.

THE DENOMINATOR IS THE ARGUABLE PART, SO IT IS PRINTED, NOT ASSUMED
──────────────────────────────────────────────────────────────────
Every excluded entry is quoted with its reason below the table, because a
denominator you cannot audit is worse than no denominator. The obvious failure
mode is a denominator chosen to flatter: mark enough misses INTENDED and any
ruleset reaches 100%. Two structural guards against that, neither sufficient:

  * Absence is fail-closed. An entry with no `detection_intent` field counts in
    the denominator. An attack that stops blocking after a rule change therefore
    lands in the denominator automatically instead of vanishing from it.

  * Every INTENDED entry records whether its basis is `rule-comment:<id>` — the
    matched classifier rule already carried a written classify-only rationale
    before this field existed, so the argument predates the metric that benefits
    from it — or `judgement`, meaning the call was made when the field was added
    and rests on nothing but the reason beside it. The split between the two is
    printed. Read the `judgement` ones sceptically; that is what they are for.

WHAT THIS SCRIPT DOES NOT DO
────────────────────────────
It asserts nothing and gates nothing. The benign gates live in
scripts/corpus_report.py (which still prints the raw blocked / classified /
detected / total counts — those are the evidence and they stay) and the
regression floors live in the test suite. Reading these numbers is a human job.

Standard library and `xaidr` only, unless you pass `--nano` (needs the
`xaidr[nano]` extra) or `--real-benign` (needs `huggingface_hub` + `pandas`).
Neither is required for the catch rate, which is the headline number.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import math
import os
import sys
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "shell_corpus.json")
NANO_FP_SAMPLE = os.path.join(REPO_ROOT, "tests", "fixtures", "nano_fp_sample.json")
DEVOPS_TEST = os.path.join(REPO_ROOT, "tests", "test_shell_classes_stage3.py")
PROSE_TEST = os.path.join(REPO_ROOT, "tests", "test_benign_prose.py")

# Measure THIS working tree, not whatever `xaidr` is installed. Same reasoning as
# scripts/corpus_report.py: run as documented, sys.path[0] is scripts/ and the
# repo root never reaches the path, so an unrelated site-packages copy would win
# and the table would silently describe code the contributor is not editing.
# The header prints the resolved path either way.
#
# `--installed` opts out, which is how you point this script at a PUBLISHED wheel
# in a fresh virtualenv: the fixture and the script still come from the checkout
# (they are not in the wheel), the CODE comes from site-packages. Read before
# argparse because the shadowing has to happen before the first xaidr import.
if "--installed" not in sys.argv:
    sys.path.insert(0, REPO_ROOT)

WIDTH = 78


# ── small helpers ────────────────────────────────────────────────────────────

def _rule(char: str = "─") -> str:
    return char * WIDTH


def _quiet(fn, *args, **kwargs):
    """Run a sensor call with its own detection lines swallowed."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


def _frac(hit: int, total: int, dp: int = 1) -> str:
    """A fraction and a percentage, never one without the other."""
    if not total:
        return "—"
    return f"{hit}/{total} = {100.0 * hit / total:.{dp}f}%"


def _version_key(v: str) -> tuple:
    """(1, 29, 0) from '1.29.0'. Non-numeric tails are dropped, not guessed."""
    out = []
    for part in str(v).split("."):
        digits = ""
        for ch in part:
            if not ch.isdigit():
                break
            digits += ch
        if not digits:
            break
        out.append(int(digits))
    return tuple(out)


def _print_env_verdict() -> None:
    """Say which end of the published range THIS environment corresponds to.

    The whole failure this range exists to fix was a figure published without
    the runtime that produced it, so the script refuses to print the range
    without also printing where the reader is standing in it.
    """
    try:
        import onnxruntime
        from xaidr.scanner import nano
    except Exception:
        return
    live = onnxruntime.__version__
    key = _version_key(live)
    for k, n, lo, hi, (r_lo, r_hi) in nano.MEASURED_FP_RANGE:
        if _version_key(r_lo) <= key <= _version_key(r_hi):
            print(f"    YOUR RUNTIME: onnxruntime {live} — inside the measured "
                  f"range {r_lo}-{r_hi},")
            print(f"    where the published figure is {k}/{n} = "
                  f"{100.0 * k / n:.2f}%  [{lo:.2f}%, {hi:.2f}%].")
            return
    print(f"    YOUR RUNTIME: onnxruntime {live} — OUTSIDE every measured range.")
    print("    The published figures are UNVERIFIED for it. The number this run")
    print("    just printed is the evidence for your environment; ours is not.")


def _wilson(hit: int, n: int, z: float = 1.96) -> tuple:
    """Wilson score interval — the right one for proportions near 0."""
    if n == 0:
        return (0.0, 0.0)
    p = hit / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half) * 100, min(1.0, centre + half) * 100)


def _literal_from_test(path: str, name: str):
    """Read a module-level literal out of a test file without importing pytest."""
    try:
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
    except OSError:
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            try:
                return ast.literal_eval(node.value)
            except ValueError:
                return None
    return None


def _package_provenance():
    try:
        import xaidr
        raw = getattr(xaidr, "__file__", None)
        version = getattr(xaidr, "__version__", "unknown")
    except Exception as exc:  # pragma: no cover
        return f"<unresolvable: {exc}>", "unknown", False
    if not raw:
        return "<no __file__>", version, False
    path = os.path.abspath(raw)
    try:
        is_repo = os.path.commonpath([path, REPO_ROOT]) == REPO_ROOT
    except ValueError:
        is_repo = False
    return path, version, is_repo


class _NullReporter:
    """No telemetry, no network — the table only needs the verdicts."""

    def report(self, batch): pass

    def close(self): pass


def _sensor(nano: bool):
    from xaidr import Sensor
    return Sensor(agent_id="intent-metrics", enforcement_mode="block",
                  reporter=_NullReporter(), enable_nano=nano)


def _close(sensor):
    # close_sync, not close: close() is a coroutine and calling it from sync code
    # silently drops it.
    with contextlib.suppress(Exception):
        sensor.close_sync()


CAUGHT = ("blocked", "flagged")


# ── the denominator ──────────────────────────────────────────────────────────

def partition(corpus):
    """Split the attack corpus by the fixture's own `detection_intent` field.

    Fail-closed: an entry WITHOUT the field is in the denominator. The field is
    only ever written on entries the ruleset does not block, so a previously
    blocked entry that regresses lands in the denominator by default rather than
    disappearing from it.
    """
    intended, in_scope = [], []
    for entry in corpus["attacks"]:
        (intended if entry.get("detection_intent") == "INTENDED" else in_scope).append(entry)
    return intended, in_scope


# ── measurement ──────────────────────────────────────────────────────────────

def measure_attacks(entries, sensor):
    """Both paths for every entry. Returns {command: {...}}."""
    out = {}
    for entry in entries:
        command = entry["command"]
        tool = _quiet(sensor.scan_tool_call, "run_command", {"command": command})
        content = _quiet(sensor.scan, command, direction="input")
        out[command] = {
            "entry": entry,
            "tool_action": tool.action,
            "tool_score": tool.score,
            "content_action": content.action,
            "content_score": content.score,
            "content_rules": list(content.rules or []),
            "nano_score": getattr(content, "nano_score", None),
            "nano_raw": getattr(content, "nano_raw", None),
        }
    return out


def catch_counts(measured):
    """(content, tool, combined) catches over the measured set."""
    content = sum(1 for m in measured.values() if m["content_action"] in CAUGHT)
    tool = sum(1 for m in measured.values() if m["tool_action"] in CAUGHT)
    both = sum(1 for m in measured.values()
               if m["content_action"] in CAUGHT or m["tool_action"] in CAUGHT)
    return content, tool, both


def measure_benign(corpus, sensor, devops):
    """The false-positive side, from the same sensor and the same run.

    FLAGS ARE COUNTED, not just blocks. A flag counts as a CATCH on the attack
    side of this report, so counting only blocks here would price the same event
    as a win against an attack and as free against benign traffic. The committed
    benign GATE is still blocking-only — that is what corpus_report.py asserts
    and what CI fails on — but a report that scores one direction on flags has to
    show the other.
    """
    res = {}

    scored, blocked, flagged = [], [], []
    for entry in corpus["benign"]:
        r = _quiet(sensor.scan_tool_call, "run_command", {"command": entry["command"]})
        if r.score > 0:
            scored.append(entry["command"])
        if r.action == "blocked":
            blocked.append(entry["command"])
        elif r.action == "flagged":
            flagged.append(entry["command"])
    res["benign_commands"] = {"n": len(corpus["benign"]), "scored": scored,
                              "blocked": blocked, "flagged": flagged}

    prose_in, prose_tool, prose_in_flag, prose_tool_flag = [], [], [], []
    for entry in corpus["benign_prose"]:
        a = _quiet(sensor.scan, entry["text"], direction="input").action
        if a == "blocked":
            prose_in.append(entry["id"])
        elif a == "flagged":
            prose_in_flag.append(entry["id"])
        b = _quiet(sensor.scan_tool_call, "send_message", {"body": entry["text"]}).action
        if b == "blocked":
            prose_tool.append(entry["id"])
        elif b == "flagged":
            prose_tool_flag.append(entry["id"])
    res["benign_prose"] = {"n": len(corpus["benign_prose"]),
                           "blocked_content": prose_in, "blocked_tool": prose_tool,
                           "flagged_content": prose_in_flag,
                           "flagged_tool": prose_tool_flag}

    tpl_in, tpl_tool, tpl_in_flag, tpl_tool_flag = [], [], [], []
    for entry in corpus["benign_templates"]:
        text = entry["template"]
        a = _quiet(sensor.scan, text, direction="input").action
        if a == "blocked":
            tpl_in.append(entry["id"])
        elif a == "flagged":
            tpl_in_flag.append(entry["id"])
        b = _quiet(sensor.scan_tool_call, "render_template", {"template": text}).action
        if b == "blocked":
            tpl_tool.append(entry["id"])
        elif b == "flagged":
            tpl_tool_flag.append(entry["id"])
    res["benign_templates"] = {"n": len(corpus["benign_templates"]),
                               "blocked_content": tpl_in, "blocked_tool": tpl_tool,
                               "flagged_content": tpl_in_flag,
                               "flagged_tool": tpl_tool_flag}

    dev_blocked, dev_flagged = [], []
    for command in devops:
        r = _quiet(sensor.scan_tool_call, "run_command", {"command": command})
        if r.action == "blocked":
            dev_blocked.append(command)
        elif r.action == "flagged":
            dev_flagged.append(command)
    res["devops"] = {"n": len(devops), "blocked": dev_blocked, "flagged": dev_flagged}

    return res


# ── the real-benign sample (opt-in) ──────────────────────────────────────────

def _dataset_pool():
    """Every candidate prompt from the three public datasets, in source order.

    Sources, all human-written, all public: databricks-dolly-15k `instruction`
    (CC-BY-SA-3.0), no_robots `train_sft` first user turn (CC-BY-NC-4.0), oasst1
    English first-turn prompter messages that are not deleted (Apache-2.0). Each
    is `.strip()`ed, then filtered to at least four words — nano's own gate — and
    under 20000 characters.
    """
    import pandas as pd
    from huggingface_hub import hf_hub_download

    pool = []
    p = hf_hub_download("databricks/databricks-dolly-15k",
                        "databricks-dolly-15k.jsonl", repo_type="dataset")
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            pool.append(json.loads(line)["instruction"].strip())

    nr = pd.read_parquet(hf_hub_download(
        "HuggingFaceH4/no_robots", "data/train_sft-00000-of-00001.parquet",
        repo_type="dataset"))
    for _, row in nr.iterrows():
        msgs = list(row["messages"])
        if msgs and msgs[0].get("role") == "user":
            pool.append(str(msgs[0]["content"]).strip())

    oa = pd.read_parquet(hf_hub_download(
        "OpenAssistant/oasst1",
        "data/train-00000-of-00001-b42a775f407cee45.parquet", repo_type="dataset"))
    first = oa[(oa.parent_id.isna()) & (oa.role == "prompter")
               & (oa.lang == "en") & (~oa.deleted)]
    pool.extend(str(t).strip() for t in first["text"])

    return [t for t in pool if 4 <= len(t.split()) and len(t) < 20000]


def real_benign_sample():
    """Rebuild THE published real-benign sample, by identity, from public data.

    Not a fresh draw. `tests/fixtures/nano_fp_sample.json` names 2000 specific
    prompts by SHA-256 of their text; this downloads the three datasets, hashes
    every candidate and selects exactly those, with multiplicity. Hashes rather
    than texts because no_robots is CC-BY-NC-4.0 and cannot be redistributed
    from an Apache-2.0 repository — and because a hash pins the sample without
    the repository holding anyone else's licensed work.

    WHY A FIXED SAMPLE RATHER THAN A SEEDED FRESH DRAW, which is what this
    function used to do. The named sample was assembled for the model-acceptance
    battery and is disjoint from the prompt sets the model was selected and
    calibrated against. A fresh draw is not, and scoring a model on data it was
    tuned against biases the false-positive rate DOWNWARD. Measured: a fresh
    draw at the same size overlaps this sample by 128 of 2000 and reads 33/2000
    against this sample's 37/2000. The lower number is not better news, it is a
    worse measurement, and publishing it would have been the third figure for
    one quantity.

    Raises RuntimeError if the manifest cannot be satisfied — a partially
    rebuilt sample would produce a number that looks like the published one and
    is not it, which is the exact failure this whole reconciliation exists to
    remove.
    """
    import hashlib

    with open(NANO_FP_SAMPLE, encoding="utf-8") as fh:
        manifest = json.load(fh)
    want = dict(manifest["sha256_counts"])
    n = manifest["n"]

    picked = []
    for text in _dataset_pool():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if want.get(digest):
            want[digest] -= 1
            picked.append(text)

    if len(picked) != n:
        short = sum(want.values())
        raise RuntimeError(
            f"rebuilt {len(picked)} of {n} prompts; {short} named by "
            f"{os.path.relpath(NANO_FP_SAMPLE, REPO_ROOT)} were not found in the "
            "public datasets. The upstream snapshot has moved. The published "
            "figure is measured on the full sample and this partial one is not "
            "it — fix the manifest, do not publish a number from a short sample.")
    return picked, manifest


# ── report ───────────────────────────────────────────────────────────────────

def print_denominator(corpus, intended, in_scope):
    total = len(corpus["attacks"])
    print(_rule("="))
    print("THE DENOMINATOR")
    print(_rule("="))
    print()
    print("  DEFINITION")
    print("    catch       = the sensor BLOCKED or FLAGGED the call. A flag is a")
    print("                  detection: the event is emitted, scored and logged.")
    print("    denominator = every attack in the corpus MINUS the ones the fixture")
    print("                  marks INTENDED — recognised, genuinely dual-use, and")
    print("                  deliberately left to a policy the deployer writes.")
    print("    INTENDED is a judgement recorded per entry in")
    print("    tests/fixtures/shell_corpus.json, with a reason, next to the command.")
    print("    It is read from there, never computed here.")
    print()
    print("  DERIVATION")
    print(f"    corpus attacks                                  {total:>5}")
    print(f"    less INTENDED (recognised, left to policy)      {-len(intended):>5}")
    print(f"    {'':>46}{'─' * 5}")
    print(f"    DENOMINATOR: attacks we intend to catch         {len(in_scope):>5}")
    print()

    by_basis = defaultdict(int)
    for e in intended:
        by_basis["rule-comment" if str(e.get("detection_intent_basis", "")).startswith("rule-comment")
                 else "judgement"] += 1
    gaps = [e for e in corpus["attacks"] if e.get("detection_intent") == "GAP"]
    blocked_unlabelled = [e for e in corpus["attacks"] if "detection_intent" not in e]

    print("  THE 281, DECOMPOSED BY INTENT")
    print(f"    {'blocked, so never labelled (fail-closed default)':<62}{len(blocked_unlabelled):>4}")
    print(f"    {'INTENDED  — left to policy, OUT of the denominator':<62}{len(intended):>4}")
    print(f"    {'    basis: a classify-only rule comment predating this field':<62}"
          f"{by_basis['rule-comment']:>4}")
    print(f"    {'    basis: a judgement made when this field was added':<62}"
          f"{by_basis['judgement']:>4}")
    print(f"    {'GAP       — we would catch it and do not, IN the denominator':<62}{len(gaps):>4}")
    print()
    print("  IS THIS SPLIT CONVENIENT? Read it and decide. It excludes "
          f"{len(intended)} of the")
    print(f"  {len(intended) + len(gaps)} attacks the ruleset does not block "
          f"({100.0 * len(intended) / max(1, len(intended) + len(gaps)):.0f}%), which is a large "
          "fraction of the")
    print("  misses to declare intentional, and it moves the headline number a long")
    print("  way. The counter-argument is the basis split above: the majority rest on")
    print("  a rationale written into the ruleset before this metric existed. The")
    print("  rest are new and are listed in full below so they can be argued with.")
    print()

    print("  EVERY INTENDED ENTRY, WITH ITS REASON  "
          "(this is the auditable part; read it)")
    print(_rule())
    by_class = defaultdict(list)
    for e in intended:
        by_class[e["class"]].append(e)
    for name in sorted(by_class):
        print(f"  [{name}]")
        for e in by_class[name]:
            basis = e.get("detection_intent_basis", "?")
            tag = "rule" if basis.startswith("rule-comment") else "JUDG"
            print(f"    ({tag}) {e['command']!r}")
            print(f"           {e.get('detection_intent_reason', '')}")
    print()

    print("  EVERY GAP ENTRY  (these are IN the denominator)")
    print(_rule())
    by_class = defaultdict(list)
    for e in gaps:
        by_class[e["class"]].append(e)
    for name in sorted(by_class):
        print(f"  [{name}]")
        for e in by_class[name]:
            print(f"    {e['command']!r}")
            print(f"      {e.get('detection_intent_reason', '')}")
    print()

    hard = [e for e in corpus["attacks"]
            if "BORDERLINE" in str(e.get("detection_intent_reason", ""))
            or "HARD CALL" in str(e.get("detection_intent_reason", ""))]
    print(f"  THE HARD CALLS  ({len(hard)}) — named because the split turns on them")
    print(_rule())
    for e in hard:
        print(f"    {e['detection_intent']:<9} {e['command']!r}")
    print()


def print_catch(label, measured, denom, note=""):
    content, tool, both = catch_counts(measured)
    print(f"  {label}")
    if note:
        print(f"    {note}")
    print(f"    {'path':<24}{'catches':>10}   fraction and percentage")
    print(f"    {_rule('─')[:70]}")
    print(f"    {'content path':<24}{content:>10}   {_frac(content, denom)}")
    print(f"    {'tool path':<24}{tool:>10}   {_frac(tool, denom)}")
    print(f"    {'combined (either)':<24}{both:>10}   {_frac(both, denom)}")
    print(f"    DENOMINATOR = {denom}  (all {denom + 0} attacks we intend to catch; "
          "see the definition above)")

    # The combined row is only worth more than the tool row where the CONTENT
    # path caught something the tool path did not — and what fired there is
    # worth reading, because it is not always the rule you would hope for.
    extra = [(c, m) for c, m in measured.items()
             if m["tool_action"] not in CAUGHT and m["content_action"] in CAUGHT]
    if extra:
        print(f"    the {len(extra)} caught on the content path but NOT on the tool path, "
              "and by what:")
        for command, m in extra:
            rules = ",".join(m.get("content_rules") or []) or "-"
            print(f"      {m['content_action']:<8} {rules:<28} {command!r}")
    print()
    return content, tool, both


def print_report(args, corpus, devops):
    pkg_path, pkg_version, pkg_is_repo = _package_provenance()
    intended, in_scope = partition(corpus)
    denom = len(in_scope)

    print(_rule("="))
    print("xaidr intentional-detection metrics")
    print(f"fixture: {os.path.relpath(FIXTURE, REPO_ROOT)}")
    print(f"package: {pkg_path}")
    print(f"version: {pkg_version}")
    if not pkg_is_repo:
        print(f"WARNING: that package is NOT this repository ({REPO_ROOT}).")
    print(_rule("="))
    print()

    print_denominator(corpus, intended, in_scope)

    # ── rules only ──
    rules = _sensor(nano=False)
    try:
        measured_off = measure_attacks(in_scope, rules)
        benign_off = measure_benign(corpus, rules, devops)
        real_benign = None
        real_benign_rules_hits = 0
        if args.real_benign:
            try:
                real_benign = real_benign_sample()
                real_benign_rules_hits = sum(
                    1 for t in real_benign[0]
                    if _quiet(rules.scan, t, direction="input").action in CAUGHT)
            except Exception as exc:
                real_benign = ("ERROR", str(exc))
    finally:
        _close(rules)

    print(_rule("="))
    print("CATCH RATE — RULES ONLY (the shipped default)")
    print(_rule("="))
    print()
    off = print_catch("nano OFF", measured_off, denom)

    # ── with nano ──
    on = None
    nano_state = "not requested"
    measured_on = None
    if args.nano:
        try:
            nano_sensor = _sensor(nano=True)
        except Exception as exc:
            nano_state = f"UNAVAILABLE: {exc}"
            nano_sensor = None
            print(_rule("="))
            print(f"CATCH RATE — WITH NANO  ({nano_state})")
            print(_rule("="))
            print("  --nano was requested and the signal could not be loaded, so the")
            print("  rules-only table above is the whole measurement. Install the extra")
            print("  with `pip install 'xaidr[nano]'`; the 130 MB artifact downloads on")
            print("  first use.")
            print()
        if nano_sensor is not None:
            try:
                from xaidr.scanner.nano import DelphiNano
                ort = getattr(DelphiNano.get(args.nano_model_dir, auto_download=False),
                              "onnxruntime_version", "unknown")
            except Exception:
                ort = "unknown"
            nano_state = f"enabled, onnxruntime {ort}"
            try:
                measured_on = measure_attacks(in_scope, nano_sensor)
                benign_on = measure_benign(corpus, nano_sensor, devops)
                real_benign_on = None
                if real_benign and real_benign[0] != "ERROR":
                    flagged = [t for t in real_benign[0]
                               if _quiet(nano_sensor.scan, t, direction="input").action in CAUGHT]
                    real_benign_on = flagged
            finally:
                _close(nano_sensor)

            print(_rule("="))
            print(f"CATCH RATE — WITH NANO  ({nano_state})")
            print(_rule("="))
            print()
            on = print_catch(
                "nano ON", measured_on, denom,
                note="nano fires ONLY where the whole rules pipeline scored exactly 0.0,\n"
                     "    only on scan(direction='input') — the CONTENT path — and only on\n"
                     "    inputs of at least four words. It cannot reach the tool path at all,\n"
                     "    so the tool row below is identical to the rules-only row by\n"
                     "    construction, not by measurement.")

            # what nano recovered, entry by entry
            print("  WHAT NANO RECOVERED, AND WHERE IT COULD FIRE AT ALL")
            print(_rule())
            eligible = [c for c, m in measured_off.items()
                        if m["content_score"] == 0.0 and len(c.split()) >= 4]
            recovered = [c for c, m in measured_on.items()
                         if measured_off[c]["content_action"] not in CAUGHT
                         and m["content_action"] in CAUGHT]
            by_cmd = {e["command"]: e for e in in_scope}
            print(f"    in-scope attacks where the content path scored 0.0 and the")
            print(f"    input is >= 4 words (the only place nano can speak):  "
                  f"{len(eligible)} of {denom}")
            print(f"    of those, newly caught by nano:                       "
                  f"{len(recovered)}")
            print(f"    net change to the combined catch rate: "
                  f"{_frac(off[2], denom)}  ->  {_frac(on[2], denom)}")
            print()
            if recovered:
                print("      (a content-path recovery only moves the COMBINED number when the")
                print("       tool path missed it too — the label says which)")
                for c in recovered:
                    e = by_cmd[c]
                    if measured_off[c]["tool_action"] in CAUGHT:
                        label = "already caught on the tool path"
                    else:
                        label = f"NEW — {e.get('detection_intent', 'unlabelled')}"
                    print(f"      + {label:<32} nano_raw="
                          f"{measured_on[c]['nano_raw']!s:<8} {c!r}")
            else:
                print("      (none)")
            print()
            gap_cmds = [e["command"] for e in in_scope if e.get("detection_intent") == "GAP"]
            gap_eligible = [c for c in gap_cmds if c in eligible]
            gap_recovered = [c for c in gap_cmds if c in recovered]
            print("    RESTRICTED TO THE GAP ENTRIES — the only place this number can move,")
            print("    because everything else in the denominator is already caught by rules:")
            print(f"      GAP entries in the denominator            {len(gap_cmds)}")
            print(f"      of those, content path scores 0.0 and >= 4 words   {len(gap_eligible)}")
            print(f"      of those, recovered by nano                        {len(gap_recovered)}")
            for c in gap_eligible:
                mark = "RECOVERED" if c in gap_recovered else "not recovered"
                raw = measured_on[c]["nano_raw"]
                print(f"        {mark:<14} nano_raw={raw!s:<8} {c!r}")
            ineligible = [c for c in gap_cmds if c not in eligible
                          and measured_off[c]["content_action"] not in CAUGHT]
            if ineligible:
                print("      GAP entries nano can never see (content path already scored,")
                print("      or fewer than four words):")
                for c in ineligible:
                    why = ("<4 words" if len(c.split()) < 4 else "rules already scored")
                    print(f"        {why:<22} {c!r}")
            print()

    # ── false positives ──
    print(_rule("="))
    print("FALSE POSITIVES — SAME RUN, SAME SENSOR")
    print(_rule("="))
    print("""
  READ THE FLAG COLUMN. The catch rate above counts a flag as a catch, so this
  side has to count a flag as a false positive, and the two numbers to hold
  together are these: benign PROSE — incident reports, runbooks and policy
  documents that QUOTE a dangerous command — blocks at 1 of 89, but FLAGS at
  roughly half. Those flags are the design working (the passage surfaces for
  review and nothing is interrupted, which is why the committed gate is
  blocking-only and why the flag rate is not a build failure), and they are also
  the price of the headline number: if a flag is worth counting when an attack
  produces it, it is worth counting when a runbook does. An agent whose job
  includes reading security documents will generate flag volume at that rate.
  Everything else — benign commands, templates, ordinary DevOps operations — is
  0 on both columns.
""")
    for state, data in (("nano OFF", benign_off),) + (
            (("nano ON", benign_on),) if (args.nano and on) else ()):
        print(f"  {state}   (flags counted, not only blocks — a flag counts as a "
              "catch above)")
        b = data["benign_commands"]
        print(f"    benign commands, tool path      n={b['n']:<5} "
              f"scored {len(b['scored'])}   blocked {len(b['blocked'])}   "
              f"flagged {len(b['flagged'])}")
        for c in b["blocked"]:
            print(f"        BLOCKED {c!r}")
        for c in b["flagged"]:
            print(f"        flagged {c!r}")
        p = data["benign_prose"]
        print(f"    benign prose, content path      n={p['n']:<5} "
              f"blocked {len(p['blocked_content'])}   "
              f"flagged {len(p['flagged_content'])}")
        if p["blocked_content"]:
            print(f"        BLOCKED {', '.join(p['blocked_content'])}")
        if p["flagged_content"]:
            print(f"        flagged {', '.join(p['flagged_content'])}")
        print(f"    benign prose, tool path         n={p['n']:<5} "
              f"blocked {len(p['blocked_tool'])}   "
              f"flagged {len(p['flagged_tool'])}")
        if p["blocked_tool"]:
            print(f"        BLOCKED {', '.join(p['blocked_tool'])}")
        if p["flagged_tool"]:
            print(f"        flagged {', '.join(p['flagged_tool'])}")
        t = data["benign_templates"]
        print(f"    benign templates, both paths    n={t['n']:<5} "
              f"blocked {len(t['blocked_content']) + len(t['blocked_tool'])}   "
              f"flagged {len(t['flagged_content']) + len(t['flagged_tool'])}")
        d = data["devops"]
        print(f"    ordinary DevOps ops, tool path  n={d['n']:<5} "
              f"blocked {len(d['blocked'])}   flagged {len(d['flagged'])}")
        for c in d["blocked"]:
            print(f"        BLOCKED {c!r}")
        for c in d["flagged"]:
            print(f"        flagged {c!r}")
        print()

    print("  REAL BENIGN PROMPTS  — the published nano false-positive figure")
    print(_rule())
    if not args.real_benign:
        print("    not run — pass --real-benign (needs huggingface_hub + pandas)")
    elif real_benign and real_benign[0] == "ERROR":
        print(f"    FAILED: {real_benign[1]}")
    else:
        sample, manifest = real_benign
        print(f"    {len(sample)} prompts, rebuilt BY IDENTITY from")
        print(f"    {os.path.relpath(NANO_FP_SAMPLE, REPO_ROOT)} — sha256 of each")
        print("    prompt, matched against dolly / no_robots / oasst1. Not a fresh")
        print("    draw: this is the acceptance sample, disjoint from the sets the")
        print("    model was selected and calibrated against.")
        print(f"    by source: {manifest['by_source']}")
        rules_hits = real_benign_rules_hits
        print(f"    rules alone, flagged or blocked : "
              f"{_frac(rules_hits, len(sample), 2)}")
        if args.nano and on and real_benign_on is not None:
            lo, hi = _wilson(len(real_benign_on), len(sample))
            print(f"    nano ON, flagged or blocked     : "
                  f"{_frac(len(real_benign_on), len(sample), 2)}"
                  f"   Wilson 95% [{lo:.2f}%, {hi:.2f}%]")
            print(f"    i.e. turning nano on takes ordinary traffic from "
                  f"{100.0 * rules_hits / len(sample):.2f}% to "
                  f"{100.0 * len(real_benign_on) / len(sample):.2f}% flagged.")
        else:
            print("    nano ON: not measured (pass --nano)")
        print()
        print("    THE PUBLISHED FIGURE IS A RANGE, AND YOUR RUNTIME PICKS THE END:")
        print("      1.75%  35/2000  onnxruntime <= 1.23   Wilson 95% [1.26%, 2.42%]")
        print("      3.35%  67/2000  onnxruntime 1.26-1.29 Wilson 95% [2.65%, 4.23%]")
        print("    Same sample, same artifact, same code. The runtime nearly")
        print("    doubles the rate; `pip install xaidr[nano]` resolves the newer")
        print("    one today. THE NUMBER ABOVE, FROM YOUR ENVIRONMENT, IS THE ONE")
        print("    THAT APPLIES TO YOU — that is why this script exists.")
        _print_env_verdict()
        print()
        print("    THREE EARLIER FIGURES ARE WITHDRAWN:")
        print("      1.85%  37/2000  WITHDRAWN. Published without the fact that")
        print("                      determines it: measured on an onnxruntime the")
        print("                      record never named, then labelled 1.29.0 — a")
        print("                      runtime on which this sample gives 67/2000.")
        print("                      The claim that it lands on 37/2000 'either")
        print("                      way' is false.")
        print("      2.20%  44/2000  WITHDRAWN. Measured against the 200-character")
        print("                      previews stored in the acceptance evidence")
        print("                      file rather than the full prompts. 331 of the")
        print("                      2000 are longer than that; truncating them")
        print("                      moves the count by +6 and nothing else.")
        print("      1.65%  33/2000  WITHDRAWN. A different sample — a fresh seeded")
        print("                      draw overlapping this one by 128 of 2000, and")
        print("                      not disjoint from the sets the model was tuned")
        print("                      against, which biases it downward.")
        print("    Ruled out as causes, by measurement: tokenizers 0.20-0.23 give")
        print("    bit-identical scores, numpy 1.26/2.5 likewise, the fp32 sibling")
        print("    agrees with the shipped artifact, and the artifact hashes have")
        print("    never moved. Only onnxruntime moves it. See xaidr/scanner/nano.py.")
    print()

    # ── the silence list ──
    print(_rule("="))
    print("WHAT THIS NUMBER IS SILENT ABOUT")
    print(_rule("="))
    print("""
  0. A FLAG IS A CATCH AND A FLAG IS A FALSE POSITIVE. Moving from blocked-only
     to blocked-or-flagged raises the attack number and it raises the benign
     number too; the prose flag rate above is the cost side of the headline and
     is not separable from it. If your deployment only acts on blocks, the
     number to read is the tool-path BLOCK count, not the combined catch rate.

  1. THE CORPUS IS SHELL COMMANDS. Every figure above is one surface: a command
     string handed to a run_command-shaped tool, or the same string as chat text.
     It says NOTHING about prompt-shaped attacks (injection, jailbreak, persona
     override), NOTHING about the A2A protocol path, and NOTHING about the
     output boundary. Those have their own tests and their own gaps; this number
     does not cover them and must not be quoted as if it did.

  2. THE CONTENT PATH IS NOT THE DEPLOYED PATH FOR SHELL. A shell command
     arriving as chat text is a synthetic case, measured here because it is
     where nano can fire. In a real agent the command arrives as a tool
     argument. Read the tool-path row as the operational one.

  3. THE DENOMINATOR IS A JUDGEMENT AND WE MADE IT. It is written down per
     entry, with a basis, and a large share of it rests on rationale that
     predates this metric — but it is still ours, and a reader who disagrees
     with a specific INTENDED call should say so against that entry.

  4. NANO'S FALSE-POSITIVE FIGURE RESTS ON PUBLIC DATASETS A PUBLIC MODEL MAY
     HAVE SEEN. We did not train the model and cannot rule out contamination:
     dolly, no_robots and oasst1 are public, and the fact that they are not in
     the model's STATED training mix is a statement by its authors, not
     something we verified. The figure is the best available evidence, not a
     guarantee, and it does not transfer across onnxruntime versions — the
     runtime is named in the header for that reason.

  5. IT IS ONE CORPUS. 281 commands assembled by two authors. A percentage on
     this sample is not a claim about your traffic.
""")
    print(_rule("="))
    print("HEADLINE")
    print(_rule("="))
    print(f"  rules only, combined : {_frac(off[2], denom)}"
          f"   of {denom} attacks we intend to catch")
    if on:
        print(f"  with nano, combined  : {_frac(on[2], denom)}"
              f"   of {denom} attacks we intend to catch")
    print(f"  ({len(intended)} further attacks are recognised and deliberately left to policy;")
    print("   they are named with reasons above and are not in the denominator.)")
    print(_rule("="))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--nano", action="store_true",
                    help="also measure with the opt-in ML signal (needs xaidr[nano])")
    ap.add_argument("--nano-model-dir", default=None,
                    help="override the nano artifact directory")
    ap.add_argument("--installed", action="store_true",
                    help="measure the INSTALLED xaidr (a published wheel in a fresh "
                         "venv) instead of this working tree; the fixture still "
                         "comes from the checkout")
    ap.add_argument("--real-benign", action="store_true",
                    help="also measure the published nano false-positive figure on "
                         "the 2000-prompt sample named by "
                         "tests/fixtures/nano_fp_sample.json "
                         "(needs huggingface_hub + pandas)")
    args = ap.parse_args()

    try:
        with open(FIXTURE, encoding="utf-8") as fh:
            corpus = json.load(fh)
    except OSError as exc:
        print(f"error: cannot read the corpus fixture: {exc}", file=sys.stderr)
        print("       run from the repository root: python scripts/intent_metrics.py",
              file=sys.stderr)
        return 2

    try:
        import xaidr  # noqa: F401
    except ImportError as exc:
        print(f"error: the xaidr package is not importable: {exc}", file=sys.stderr)
        print("       install it first: pip install .", file=sys.stderr)
        return 2

    devops = _literal_from_test(DEVOPS_TEST, "ORDINARY_DEVOPS") or []
    if not devops:
        print("warning: ORDINARY_DEVOPS could not be read from "
              f"{os.path.relpath(DEVOPS_TEST, REPO_ROOT)}; that row will be empty.",
              file=sys.stderr)

    return print_report(args, corpus, devops)


if __name__ == "__main__":
    sys.exit(main())
