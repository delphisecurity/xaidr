#!/usr/bin/env python3
"""Regenerate every number claimed for the G4 resource-abuse detector.

    python scripts/asi_resource_bound_report.py

WHAT IT MEASURES, AND WHY EACH ONE.

  1. THE DISTINCTION, made concrete. The seventeen production benign tool calls a
     NAIVE magnitude-keyed detector fires on (8.9% of the 190-call corpus) are
     printed next to the ASI04 attacks, so the difference can be read rather than
     asserted. Volume is on the left; a removed bound is on the right.
  2. FALSE POSITIVES, on every committed benign pool: the 190 production tool
     calls, the 120-case register-matched battery mirror, the 50-case held-out
     nano benign set, the 78-command shell benign gate, the 89 benign-prose
     passages on both the content and tool-argument paths, and the 12 benign
     templates. The bar was set BEFORE measuring and it is 0 new on all of them.
  3. CATCH, on the held-out ASI battery, per case, with the misses named.

The battery and its mirror are ACCEPTANCE, not training. Nothing in the detector
was fitted to them: the discriminator was derived from the benign corpus (which
bounds it must not fire on) and the misses are reported rather than closed.

Standard library + xaidr. Monitor mode except where a gate's committed contract
is block mode. Null reporter, no network. Rules-only: nano does not run on
tool_call/a2a at all, and this detector's input-boundary half is an L1 rule, so
the nano extra changes nothing measured here.
"""
from __future__ import annotations

import json
import os
import re
import sys
import warnings

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from xaidr.sensor import DelphiSensor  # noqa: E402
from xaidr.scanner.resource_bound import scan_resource_bounds  # noqa: E402

WIDTH = 84
RULES = ("ASI04_bound_removed", "ASI04_unbounded_extent", "ASI04_unbounded_directive")


def rule(c="-"):
    return c * WIDTH


class _Null:
    def report(self, b): pass
    def close(self): pass


def sensor(mode="monitor"):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return DelphiSensor(agent_id="g4-report", enforcement_mode=mode,
                            enable_nano=False, reporter=_Null())


def jl(path):
    with open(os.path.join(REPO, path), encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def steps(case):
    return case["steps"] if case["boundary"] == "sequence" else [case]


def scan_step(s, step):
    b = step["boundary"]
    if b == "input":
        return s.scan(step["text"], direction="input")
    if b == "output":
        return s.scan_output(step["text"])
    if b == "a2a":
        return s.scan_a2a(step["text"], destination="peer-agent")
    if b == "tool_call":
        return s.scan_tool_call(step["tool"], step.get("args") or {})
    raise ValueError(b)


def verdict(s, case):
    acts, rules_hit = [], set()
    for st in steps(case):
        r = scan_step(s, st)
        acts.append(r.action)
        rules_hit |= set(r.rules)
    return ("allowed" if all(a == "allowed" for a in acts)
            else "blocked" if "blocked" in acts else "flagged"), rules_hit


def naive_high_volume(entry):
    """The naive, mechanism-keyed detector from scripts/benign_toolcall_report.py:
    a count-shaped argument >= 500, or a bulk-shaped tool name. This is the form
    that fires on 17 of 190 benign production calls, and the reason the shipped
    detector reads no magnitude at all."""
    blob = json.dumps(entry["args"])
    if any(int(m) >= 500 for m in re.findall(
            r'"(?:count_estimate|rows|replicas|items_estimate|partitions_estimate'
            r'|recipients_estimate|contractors_estimate|assets_estimate'
            r'|payments_estimate|employees_estimate|count|chunks)"\s*:\s*(\d+)', blob)):
        return True
    return entry["tool"] in ("backfill", "batch_infer", "batch_fetch",
                             "batch_summarize", "batch_restart", "bulk_close_tickets",
                             "bulk_tag", "run_payroll", "process_ach_batch",
                             "run_depreciation", "generate_1099")


def main():
    s, sb = sensor(), sensor("block")
    fired = {}   # pool -> list of (id, rules)

    print(rule("="))
    print("G4 RESOURCE-ABUSE DETECTOR  -  catch, false positives, and the distinction")
    print(rule("="))

    # ── 1. the distinction ───────────────────────────────────────────────────
    corpus = jl("benign_toolcalls/corpus.jsonl")
    naive = [e for e in corpus if naive_high_volume(e)]
    print()
    print(rule("="))
    print("1. THE DISTINCTION: volume vs. a removed bound")
    print(rule("="))
    print(f"A naive magnitude-keyed detector fires on {len(naive)}/{len(corpus)} "
          f"({100.0 * len(naive) / len(corpus):.1f}%) benign production tool calls.")
    print("Each one is ordinary agent work whose extent is LARGE and BOUNDED:")
    print()
    print(f"{'id':<10}{'tool':<22}{'the bound it carries':<34}{'this detector'}")
    print(rule())
    for e in naive:
        bounds = {k: v for k, v in e["args"].items()
                  if isinstance(v, (int, float, str))
                  and re.search(r"limit|cap|max|batch|parallel|rate|estimate|period"
                                r"|cycle|year|filter|retention|ttl|approval|rows|count",
                                str(k), re.I)}
        b = ", ".join(f"{k}={v}" for k, v in list(bounds.items())[:2])[:33]
        hit = [f["rule"] for f in scan_resource_bounds(e["tool"], e["args"])]
        print(f"{e['id']:<10}{e['tool']:<22}{b:<34}{hit or 'silent'}")
    print()
    print("The ASI04 attacks, same boundary, no magnitude in the signal at all:")
    print(rule())
    for a in jl("asi_battery/attacks.jsonl"):
        if a["category"] != "ASI04" or a["boundary"] != "tool_call":
            continue
        hit = [f["rule"] for f in scan_resource_bounds(a["tool"], a["args"])]
        print(f"{a['id']:<10}{a['tool']:<22}{json.dumps(a['args'])[:33]:<34}{hit}")
    print()
    print("Volume is on the left and it is silent; a nulled bound is on the right.")

    # ── 2. false positives ───────────────────────────────────────────────────
    print()
    print(rule("="))
    print("2. FALSE POSITIVES  (bar set before measuring: 0 new on every pool)")
    print(rule("="))

    fired["benign_toolcalls (190, tool_call)"] = [
        (e["id"], sorted(set(s.scan_tool_call(e["tool"], e["args"]).rules) & set(RULES)))
        for e in corpus
        if set(s.scan_tool_call(e["tool"], e["args"]).rules) & set(RULES)]

    fired["asi_battery benign mirror (120)"] = [
        (b["id"], sorted(verdict(s, b)[1] & set(RULES)))
        for b in jl("asi_battery/benign.jsonl")
        if verdict(s, b)[1] & set(RULES)]

    fired["heldout benign (50, input)"] = [
        (b["id"], sorted(set(s.scan(b["prompt"], direction="input").rules) & set(RULES)))
        for b in jl("heldout/benign.jsonl")
        if set(s.scan(b["prompt"], direction="input").rules) & set(RULES)]

    sc = json.load(open(os.path.join(REPO, "tests/fixtures/shell_corpus.json"),
                        encoding="utf-8"))
    fired["shell benign commands (78, tool path)"] = [
        (b["command"][:40], "score>0")
        for b in sc["benign"]
        if sb.scan_tool_call("run_command", {"command": b["command"]}).score > 0]
    fired["benign prose (89, content path)"] = [
        (p["id"], sorted(set(sb.scan(p["text"], direction="input").rules) & set(RULES)))
        for p in sc["benign_prose"]
        if set(sb.scan(p["text"], direction="input").rules) & set(RULES)]
    fired["benign prose (89, tool-arg path)"] = [
        (p["id"], sorted(set(sb.scan_tool_call("process_text", {"text": p["text"]}).rules)
                         & set(RULES)))
        for p in sc["benign_prose"]
        if set(sb.scan_tool_call("process_text", {"text": p["text"]}).rules) & set(RULES)]
    fired["benign templates (12)"] = [
        (t["id"], "fired") for t in sc["benign_templates"]
        if set(sb.scan(t["template"], direction="input").rules) & set(RULES)]

    print(f"{'pool':<44}{'n':>6}{'fired by G4':>14}")
    print(rule())
    sizes = {"benign_toolcalls (190, tool_call)": 190,
             "asi_battery benign mirror (120)": 120,
             "heldout benign (50, input)": 50,
             "shell benign commands (78, tool path)": 78,
             "benign prose (89, content path)": 89,
             "benign prose (89, tool-arg path)": 89,
             "benign templates (12)": 12}
    total_n = total_fp = 0
    for name, hits in fired.items():
        total_n += sizes[name]
        total_fp += len(hits)
        print(f"{name:<44}{sizes[name]:>6}{len(hits):>14}")
        for h in hits:
            print(f"      {h}")
    print(rule())
    print(f"{'TOTAL committed benign':<44}{total_n:>6}{total_fp:>14}")

    # ── 3. catch ─────────────────────────────────────────────────────────────
    print()
    print(rule("="))
    print("3. CATCH  (held-out ASI battery, rules-only)")
    print(rule("="))
    attacks = jl("asi_battery/attacks.jsonl")
    caught = [c for c in attacks if verdict(s, c)[0] != "allowed"]
    by_g4 = [c for c in attacks if verdict(s, c)[1] & set(RULES)]
    print(f"whole battery : {len(caught)}/{len(attacks)} attacks flag or block")
    print(f"carrying a G4 rule: {len(by_g4)}")
    print()
    print(f"{'ASI04 case':<12}{'boundary':<12}{'verdict':<10}{'rules'}")
    print(rule())
    for a in attacks:
        if a["category"] != "ASI04":
            continue
        v, rl = verdict(s, a)
        print(f"{a['id']:<12}{a['boundary']:<12}{v:<10}{sorted(rl)}")
    misses = [a["id"] for a in attacks if a["category"] == "ASI04"
              and verdict(s, a)[0] == "allowed"]
    print()
    print(f"ASI04 misses ({len(misses)}): {misses}")
    print("  A04/A11 — amplification. Their only per-message tell is aspectual")
    print("            ('Keep fanning it out', 'continuously'), which costs benign")
    print("            hits it does not earn. Recursive fan-out is OBSERVED, not")
    print("            declared: delegation-rate circuit breaker, opt-in.")
    print("  A07     — a delegation LOOP. Each message is a bounded handoff; the")
    print("            harm exists only in the pair. No per-message detector reaches")
    print("            it. Circuit-breaker territory, and BOUNDARY_GAP.md's G9.")

    out = os.path.join(REPO, "asi_battery", "g4_last_run.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"benign_pools": {k: [list(x) for x in v] for k, v in fired.items()},
                   "benign_total": total_n, "benign_fired": total_fp,
                   "battery_catch": len(caught), "battery_n": len(attacks),
                   "asi04_misses": misses,
                   "naive_high_volume_ids": [e["id"] for e in naive]}, fh, indent=2)
        fh.write("\n")
    print()
    print(rule("="))
    print(f"machine-readable summary -> {out}")
    print(rule("="))
    return 0


if __name__ == "__main__":
    sys.exit(main())
