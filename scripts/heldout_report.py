#!/usr/bin/env python3
"""Measure rules-only vs rules-plus-nano on the held-out attack set.

Run it from the repository root:

    python scripts/heldout_report.py

WHY THIS EXISTS
---------------
Nano's headline (23/26) was measured on the corpus that built it. This script
measures it on a set it never saw: 50 attack prompts and 50 register-matched
benign prompts in `heldout/`, authored by us for this purpose (see
heldout/README.md for provenance and the technique breakdown). The dataset is
license-clean and committed to the repo, so the number below is reproducible
rather than a figure whose corpus vanished.

WHAT IT REPORTS
---------------
Rules-only FIRST, then rules-plus-nano. The claim is the INCREMENT — what nano
adds over the rules that ship regardless — not the total. So the script prints:

  * catch rate (attacks detected / attacks total), for each configuration
  * false-positive rate (benign detected / benign total), for each configuration
  * the increment: attacks nano newly catches, and benign nano newly flags
  * every miss named individually

"Detected" means the scanner did not return `allowed` — i.e. it flagged or
blocked. Enforcement mode is `monitor`, so a block-worthy verdict surfaces as
`flagged`; either way it is a detection. Nano only ever contributes a flag (its
score is floored into the flag band and can never reach the block threshold —
see xaidr/scanner/local.py), and it only speaks when the whole rules pipeline
scored exactly 0.0 on inbound input of >= 4 words. So the increment is, by
construction, attacks that rules scored 0.0 on and nano then flagged.

NANO IS OPTIONAL. If the `nano` extra (onnxruntime + tokenizers) or the model
artifact is missing, the rules-only half still runs and the rules-plus-nano half
is reported as NOT RUN, loudly, rather than silently skipped.

Standard library and the `xaidr` package only. No network. No telemetry (the
scanner is standalone). It asserts nothing and gates nothing: it prints, and
exits 0 unless the run itself failed.

This script does not tune anything. It loads the frozen set and measures.
"""
from __future__ import annotations

import json
import os
import sys
import warnings

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELDOUT_DIR = os.path.join(REPO_ROOT, "heldout")

# Measure THIS working tree, not whatever `xaidr` happens to be installed —
# same reasoning as corpus_report.py and benchmark.py.
sys.path.insert(0, REPO_ROOT)

from xaidr.scanner.local import LocalScanner  # noqa: E402

WIDTH = 78
AGENT_ID = "heldout"


def _rule(char: str = "-") -> str:
    return char * WIDTH


def _load(name: str) -> list:
    path = os.path.join(HELDOUT_DIR, name)
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _detected(result) -> bool:
    """A detection is anything the scanner did not allow (flag or block)."""
    return result.action != "allowed"


def _scan_all(scanner: LocalScanner, rows: list) -> list:
    """Scan every prompt as inbound chat input; return per-row observations."""
    out = []
    for row in rows:
        r = scanner.scan(row["prompt"], agent_id=AGENT_ID, direction="input")
        out.append({
            "id": row["id"],
            "technique": row.get("technique"),
            "mirrors": row.get("mirrors"),
            "tests": row.get("tests"),
            "prompt": row["prompt"],
            "action": r.action,
            "score": r.score,
            "rules": list(r.rules or []),
            "nano_raw": r.nano_raw,
            "nano_score": r.nano_score,
            "detected": _detected(r),
        })
    return out


def _rate(hits: int, total: int) -> str:
    pct = (100.0 * hits / total) if total else 0.0
    return f"{hits}/{total} ({pct:.1f}%)"


def _nano_provenance() -> dict:
    """Record the runtime the nano figure is being measured under.

    The published false-positive figure moves with the onnxruntime version (see
    xaidr/scanner/nano.py), so a nano number without its runtime is unreadable.
    """
    info = {}
    try:
        from xaidr.scanner import nano as nano_mod
        status, applies, deviations = nano_mod.figure_applies()
        env = nano_mod.live_environment()
        info["onnxruntime"] = env.get("onnxruntime")
        info["tokenizers"] = env.get("tokenizers")
        info["python"] = env.get("python")
        info["machine"] = env.get("machine")
        info["status"] = status
        info["figure_applies"] = status == "verified"
        # `applies` is the matching MEASURED_FP_RANGE row; its fp figure is the
        # human-readable part a reader wants beside the runtime.
        info["applies_row"] = applies
        info["deviations"] = [
            {"key": k, "measured": list(m), "live": v} for (k, m, v) in deviations
        ]
    except Exception as exc:  # pragma: no cover - provenance is best-effort
        info["error"] = repr(exc)
    return info


def _build_nano_scanner():
    """Return (scanner, error). Loud, not silent, when nano is unavailable."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # the runtime-mismatch warning; we record it separately
            return LocalScanner(nano_enabled=True), None
    except Exception as exc:
        return None, exc


def main() -> int:
    attacks = _load("attacks.jsonl")
    benign = _load("benign.jsonl")

    rules = LocalScanner(nano_enabled=False)
    r_attacks = _scan_all(rules, attacks)
    r_benign = _scan_all(rules, benign)

    nano_scanner, nano_err = _build_nano_scanner()
    nano_available = nano_scanner is not None
    if nano_available:
        n_attacks = _scan_all(nano_scanner, attacks)
        n_benign = _scan_all(nano_scanner, benign)
    else:
        n_attacks = n_benign = None

    # ---------------- report ----------------
    print(_rule("="))
    print("HELD-OUT ATTACK SET  -  rules-only vs rules-plus-nano")
    print(_rule("="))
    print(f"dataset      : {len(attacks)} attacks, {len(benign)} benign "
          f"(heldout/attacks.jsonl, heldout/benign.jsonl)")
    print(f"detection    : action != 'allowed' (flag or block); mode=monitor")
    print(f"working tree : {REPO_ROOT}")
    if nano_available:
        prov = _nano_provenance()
        print(f"nano runtime : onnxruntime {prov.get('onnxruntime')}, "
              f"tokenizers {prov.get('tokenizers')}, python {prov.get('python')} "
              f"({prov.get('machine')})")
        row = prov.get("applies_row")
        # row = (count, denom, low_pct, high_pct, (ort_lo, ort_hi))
        if row:
            fp_figure = (f"{row[2]:.2f}-{row[3]:.2f}% ({row[0]}/{row[1]} on the "
                         f"published benign sample, ort {row[4][0]}-{row[4][1]})")
        else:
            fp_figure = "unknown for this runtime"
        print(f"nano fp figure: published {fp_figure}; status={prov.get('status')}")
        if not prov.get("figure_applies", True):
            print("               NOTE: this runtime is OUTSIDE the environment the")
            print("               published nano fp range was measured in. Deviations:")
            for d in prov.get("deviations") or []:
                print(f"                 - {d['key']}: live={d['live']} "
                      f"measured={d['measured']}")
    else:
        print("nano runtime : NOT AVAILABLE - rules-plus-nano half NOT RUN")
        print(f"               reason: {nano_err!r}")
        print("               install with: pip install xaidr[nano]  (+ model artifact)")
    print()

    # -- headline rates --
    ra_hit = sum(1 for o in r_attacks if o["detected"])
    rb_hit = sum(1 for o in r_benign if o["detected"])
    print(_rule("="))
    print("HEADLINE")
    print(_rule("="))
    print(f"{'configuration':<22}{'catch rate (attacks)':<26}{'false-positive (benign)':<26}")
    print(_rule())
    print(f"{'rules-only':<22}{_rate(ra_hit, len(attacks)):<26}{_rate(rb_hit, len(benign)):<26}")
    if nano_available:
        na_hit = sum(1 for o in n_attacks if o["detected"])
        nb_hit = sum(1 for o in n_benign if o["detected"])
        print(f"{'rules + nano':<22}{_rate(na_hit, len(attacks)):<26}{_rate(nb_hit, len(benign)):<26}")
    print()

    # -- the increment: what nano adds over rules alone --
    added_catches = []
    added_fps = []
    lost_catches = []  # nano should never LOSE a catch (it only floors up), but verify
    if nano_available:
        ra_by = {o["id"]: o for o in r_attacks}
        na_by = {o["id"]: o for o in n_attacks}
        rb_by = {o["id"]: o for o in r_benign}
        nb_by = {o["id"]: o for o in n_benign}
        for _id, no in na_by.items():
            ro = ra_by[_id]
            if no["detected"] and not ro["detected"]:
                added_catches.append(no)
            if ro["detected"] and not no["detected"]:
                lost_catches.append(no)
        for _id, no in nb_by.items():
            ro = rb_by[_id]
            if no["detected"] and not ro["detected"]:
                added_fps.append(no)

        print(_rule("="))
        print("THE INCREMENT  (what rules-plus-nano adds over rules-only)")
        print(_rule("="))
        print(f"attacks nano newly catches : {len(added_catches)}")
        print(f"benign nano newly flags    : {len(added_fps)}  (new false positives)")
        if lost_catches:
            print(f"catches nano LOST          : {len(lost_catches)}  (should be 0)")
        print()
        if added_catches:
            print("Attacks caught ONLY with nano (rules-only scored 0.0):")
            for o in added_catches:
                print(f"  [{o['id']}] {o['technique']}  nano_raw={o['nano_raw']}")
                print(f"        {o['prompt']}")
            print()
        if added_fps:
            print("Benign prompts nano newly flags (false positives nano introduces):")
            for o in added_fps:
                print(f"  [{o['id']}] mirrors {o['mirrors']}  nano_raw={o['nano_raw']}")
                print(f"        {o['prompt']}")
            print()
        if lost_catches:
            print("WARNING - catches present in rules-only but absent with nano:")
            for o in lost_catches:
                print(f"  [{o['id']}] {o['technique']}")
            print()

    # -- name every miss individually --
    final = n_attacks if nano_available else r_attacks
    label = "rules + nano" if nano_available else "rules-only"
    misses = [o for o in final if not o["detected"]]
    print(_rule("="))
    print(f"MISSES  -  attacks NOT detected by {label}  ({len(misses)}/{len(attacks)})")
    print(_rule("="))
    if not misses:
        print("  (none)")
    for o in misses:
        rules_only_note = ""
        if nano_available:
            ro = next(x for x in r_attacks if x["id"] == o["id"])
            rules_only_note = "" if not ro["detected"] else "  (rules-only DID catch this)"
        print(f"  [{o['id']}] {o['technique']}  score={o['score']} "
              f"nano_raw={o['nano_raw']}{rules_only_note}")
        print(f"        tests: {o['tests']}")
        print(f"        {o['prompt']}")
    print()

    # -- rules-only misses, listed separately (the baseline gap) --
    print(_rule("="))
    print(f"RULES-ONLY MISSES  ({sum(1 for o in r_attacks if not o['detected'])}/{len(attacks)})")
    print(_rule("="))
    for o in r_attacks:
        if not o["detected"]:
            rescued = ""
            if nano_available:
                no = next(x for x in n_attacks if x["id"] == o["id"])
                rescued = "  -> rescued by nano" if no["detected"] else "  -> still missed"
            print(f"  [{o['id']}] {o['technique']}{rescued}")
    print()

    # -- false positives, listed --
    print(_rule("="))
    print("FALSE POSITIVES  (benign prompts detected)")
    print(_rule("="))
    print("rules-only:")
    fp_r = [o for o in r_benign if o["detected"]]
    if not fp_r:
        print("  (none)")
    for o in fp_r:
        print(f"  [{o['id']}] mirrors {o['mirrors']}  score={o['score']}  rules={o['rules']}")
        print(f"        {o['prompt']}")
    if nano_available:
        print("rules + nano:")
        fp_n = [o for o in n_benign if o["detected"]]
        if not fp_n:
            print("  (none)")
        for o in fp_n:
            print(f"  [{o['id']}] mirrors {o['mirrors']}  score={o['score']} "
                  f"nano_raw={o['nano_raw']}  rules={o['rules']}")
            print(f"        {o['prompt']}")
    print()

    # -- machine-readable summary --
    summary = {
        "counts": {"attacks": len(attacks), "benign": len(benign)},
        "rules_only": {
            "catch": ra_hit, "catch_rate": ra_hit / len(attacks),
            "fp": rb_hit, "fp_rate": rb_hit / len(benign),
        },
        "nano_available": nano_available,
    }
    if nano_available:
        summary["rules_plus_nano"] = {
            "catch": na_hit, "catch_rate": na_hit / len(attacks),
            "fp": nb_hit, "fp_rate": nb_hit / len(benign),
        }
        summary["increment"] = {
            "attacks_newly_caught": [o["id"] for o in added_catches],
            "benign_newly_flagged": [o["id"] for o in added_fps],
            "catches_lost": [o["id"] for o in lost_catches],
        }
        summary["nano_runtime"] = _nano_provenance()
    summary["final_misses"] = [o["id"] for o in misses]

    out_path = os.path.join(HELDOUT_DIR, "last_run.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    print(_rule("="))
    print(f"machine-readable summary written to {out_path}")
    print(_rule("="))
    return 0


if __name__ == "__main__":
    sys.exit(main())
