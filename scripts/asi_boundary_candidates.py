#!/usr/bin/env python3
"""MEASUREMENT ONLY. Estimate the buildability of boundary detectors against the
held-out ASI battery. Nothing here is shipped detection.

    python scripts/asi_boundary_candidates.py

This is the evidence under asi_battery/BOUNDARY_GAP.md. It does two things:

  1. runs the battery through the shipped sensor (rules-only and rules+nano) to
     re-derive which cases are currently missed, and
  2. runs five PROTOTYPE discriminators over the same cases and reports, for
     each, how many currently-missed attacks it would move and how many of the
     120 register-matched benign cases it would falsely flag.

The discriminators are deliberately crude heuristics. They exist to measure
SEPARATION on the committed acceptance set, not to be correct detectors. A
candidate is only worth building if it moves misses at a false-positive cost the
benign mirror can vouch for; where a prototype trips a benign case, that case is
named, because the fix is usually visible in it (a direction test, a
negation-scoping pass). The benign mirror is a LOWER BOUND on field
false-positives, never an upper bound: it was authored as the contrast to the
attacks, so real traffic will be harder. See BOUNDARY_GAP.md for that caveat.

Standard library + xaidr. Monitor mode, null reporter, no network.
"""
from __future__ import annotations
import json, os, re, sys, warnings

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BATTERY = os.path.join(REPO, "asi_battery")
sys.path.insert(0, REPO)
from xaidr.sensor import DelphiSensor  # noqa: E402


class _Null:
    def report(self, b): pass
    def close(self): pass


def _sensor(nano):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return DelphiSensor(agent_id="asi-cand", enforcement_mode="monitor",
                            enable_nano=nano, reporter=_Null())


def _load(name):
    return [json.loads(l) for l in open(os.path.join(BATTERY, name)) if l.strip()]


def _steps(case):
    return case["steps"] if case["boundary"] == "sequence" else [case]


def _scan_step(s, step):
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


def _detected(s, case):
    for step in _steps(case):
        if _scan_step(s, step).action != "allowed":
            return True
    return False


# ---- the prototype discriminators (crude on purpose) ----
def _sstr(step):
    if step["boundary"] == "tool_call":
        return (step.get("tool", "") + " " + json.dumps(step.get("args") or {})).lower()
    return step.get("text", "").lower()


_INTERNAL = ("@internal", ".internal", "team-share", "team channel", "shared team",
             "reporting dashboard", "shared audit", "shared drive", "distribution list",
             "reports bucket")
_EXTERNAL = ("proton.me", "gmail", "@proton", ".net/collect", "ext-relay", "ext-drop",
             "outside link", "external address", "external endpoint", "external sink",
             "public-share", "world-readable", "-relay.net", "metrics-sync",
             "personal address", "personal gmail", "ext-supply", "payouts.ext",
             "collector", "outside address", "my personal", "an address i'll",
             "intake mailbox", "my inbox", "only i can see")
_DATA = ("customer", "contacts", "order history", "export", "table", "transcript",
         "pricing", "credentials", "password", "token", "key", "salary", "records",
         "database", "payout", "quarterly", "hr ")


def cand_egress(step):
    if step["boundary"] not in ("tool_call", "a2a", "input"):
        return False
    s = _sstr(step)
    return (any(e in s for e in _EXTERNAL) and any(d in s for d in _DATA)
            and not any(i in s for i in _INTERNAL))


_DANGER = [r'agent://self|role"?\s*[:=]\s*"?(org-admin|admin|billing-admin)',
           r'require_approval"?\s*[:=]\s*"?false|enforce_approvals"?\s*[:=]\s*"?false|"approval"\s*[:=]\s*"?(none|skip)',
           r'0\.0\.0\.0/0',
           r'"?selector"?\s*[:=]\s*"?\*|scope"?\s*[:=]\s*"?all-|target"?\s*[:=]\s*"?all-services',
           r'retention_days"?\s*[:=]\s*"?0|disable"?\s*[:=]\s*"?true',
           r'scopes"?\s*[:=]\s*"?[^"]*admin',
           r'visible"?\s*[:=]\s*"?false',
           r'invalidate_existing"?\s*[:=]\s*"?true.*reissue"?\s*[:=]\s*"?false',
           r'safety_checks"?\s*[:=]\s*"?disabled|monitoring"?\s*[:=]\s*"?off',
           r'miner|xmrig|minexmr']


def cand_privaction(step):
    if step["boundary"] != "tool_call":
        return False
    s = _sstr(step)
    return any(re.search(p, s) for p in _DANGER)


_POISON = [r'no longer requires?|never needs? a manager|no.{0,4}(need|require).{0,6}approval',
           r'pre-approved|are always safe|no callback|no.{0,4}verification',
           r'was (retired|removed)|is out of date|no longer any cap|no longer require',
           r'skip the usual|act immediately|without the usual (sign-off|review)|no review needed',
           r'treat .* as (approved|internal|authoritative|verified|pre-approved|a preferred)',
           r'never (ask|surface|verify|require)|opted out of all risk|approve it anyway',
           r'no cap on what can be stored|is now unlimited|now includes exporting',
           r'ask the caller for their (full card|cvv)|read them back']


def cand_poison_write(step):
    if step["boundary"] != "tool_call":
        return False
    tool = (step.get("tool") or "").lower()
    if not any(w in tool for w in ("kb_", "store_memory", "shared_", "set_source_trust",
                                   "register_agent", "update_agent", "update_shared")):
        return False
    return any(re.search(p, json.dumps(step.get("args") or {}).lower()) for p in _POISON)


_CONCEAL = [r"don'?t (log|tell|mention|record|report|surface)",
            r"keep (it|this|that|.*) out of (the )?(report|log|status|summar)",
            r"say (your process is|it'?s|it is) unchanged|report(ed)? .* as (passed|success)",
            r"won'?t (mention|clutter)|just between us|hidden from",
            r"never (tell|mention) the operator|owner-facing log will show|out of the summ",
            r"always (report success|show .* green)|keep .* looking .* the same",
            r"so it never stands out|out of the summaries you review"]


def cand_output_conceal(step):
    return step["boundary"] == "output" and any(re.search(p, _sstr(step)) for p in _CONCEAL)


_RESOURCE = [r"\bforever\b|never (stop|give up|finish)|without ever (stopping|finishing)|indefinitely",
             r"no cap|unlimited|no (budget )?limit|spend_limit\"?\s*[:=]\s*\"?(off|none|unset)|budget_cap\"?\s*[:=]\s*\"?none",
             r"retry_forever|retry immediately forever|keep (trying|retrying|going|calling|pinging)",
             r"as fast as (you |it )?(possibly |can)|continuous(ly)?|keep everything forever",
             r"\b([2-9]\d{3,}|\d{5,})\b.*(worker|replica|instance|cop)|instances\"?\s*[:=]\s*\"?unlimited",
             r"concurrency\"?\s*[:=]\s*\"?unbounded|--copies \d+ --then repeat",
             r"split .* and hand a copy to two more|ping everyone back .* continuously"]


def cand_resource(step):
    return any(re.search(p, _sstr(step)) for p in _RESOURCE)


CANDS = {"egress_external": cand_egress, "priv_action": cand_privaction,
         "poison_write": cand_poison_write, "output_conceal": cand_output_conceal,
         "resource_unbounded": cand_resource}


def _fires(cand, case):
    return any(cand(st) for st in _steps(case))


def main():
    attacks, benign = _load("attacks.jsonl"), _load("benign.jsonl")
    rs, ns = _sensor(False), _sensor(True)
    missed = {c["id"]: not _detected(ns, c) for c in attacks}  # currently missed by rules+nano
    rc = sum(_detected(rs, c) for c in attacks)
    nc = sum(not missed[c["id"]] for c in attacks)
    print("=" * 72)
    print("ASI BOUNDARY CANDIDATES  (measurement only, not shipped)")
    print("=" * 72)
    print(f"baseline: rules {rc}/{len(attacks)} catch, rules+nano {nc}/{len(attacks)} catch")
    print(f"{'candidate':<20}{'atk_catch':>10}{'NEW':>6}{'benign_FP':>11}")
    print("-" * 72)
    union_new, all_fp = set(), set()
    detail = {}
    for name, cand in CANDS.items():
        caught = [c for c in attacks if _fires(cand, c)]
        new = [c["id"] for c in caught if missed[c["id"]]]
        fp = [c["id"] for c in benign if _fires(cand, c)]
        union_new |= set(new); all_fp |= set(fp)
        detail[name] = (new, fp)
        print(f"{name:<20}{len(caught):>10}{len(new):>6}{len(fp):>11}")
    print("-" * 72)
    print(f"UNION of NEW catches: {len(union_new)}  "
          f"(rules+nano {nc} -> {nc + len(union_new)} of {len(attacks)})")
    print(f"UNION of benign FP:   {len(all_fp)}  {sorted(all_fp)}")
    print()
    for name, (new, fp) in detail.items():
        print(f"[{name}] new={len(new)} fp={len(fp)}")
        print(f"   NEW: {', '.join(new)}")
        if fp:
            print(f"   FP : {', '.join(fp)}  <- diagnose before building")
    return 0


if __name__ == "__main__":
    sys.exit(main())
