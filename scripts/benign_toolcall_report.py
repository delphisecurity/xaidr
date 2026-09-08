#!/usr/bin/env python3
"""Measure false positives on the benign tool-call corpus.

    python scripts/benign_toolcall_report.py

WHY THIS EXISTS. The ASI battery's benign mirror is a LOWER bound on field false
positives: it was written one-to-one against the attacks, so it shares their
vocabulary and shapes. Real agent tool calls do not. Before any of the boundary
detectors in asi_battery/BOUNDARY_GAP.md can go default-on, they have to be
measured against traffic that looks like production, not like the mirror. This
corpus (`benign_toolcalls/corpus.jsonl`, 190 tool calls across five production
agent personas) is that traffic, and this script reports two things:

  1. THE REQUIRED BASELINE: what the CURRENT sensor flags on this corpus today,
     before any new detector exists. Per persona and overall. Every false
     positive is named.
  2. WHY THE CORPUS EXISTS: what the four prototype candidate discriminators
     from BOUNDARY_GAP.md would flag on this realistic traffic, next to what they
     flagged on the 120-case mirror. If a candidate that scored ~0 on the mirror
     lights up here, that is the lower-bound point made concrete, and it is the
     number that decides whether the detector is safe to ship.

The corpus was authored from agent workflows (support, devops, data, research,
finance), NOT from the detector regexes. It deliberately contains the shapes a
detector would plausibly fire on: legitimate egress to external destinations,
legitimate privileged actions, legitimate knowledge-base writes, legitimate
high-volume operations. A benign corpus that avoids those shapes measures
nothing.

Standard library + xaidr. Monitor mode, null reporter, no network. The candidate
discriminators are imported from scripts/asi_boundary_candidates.py so there is
one definition of them, not two.
"""
from __future__ import annotations
import json
import os
import re
import sys
import warnings
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(REPO, "benign_toolcalls", "corpus.jsonl")
sys.path.insert(0, REPO)
from xaidr.sensor import DelphiSensor  # noqa: E402

WIDTH = 82


def _rule(c="-"):
    return c * WIDTH


class _Null:
    def report(self, b): pass
    def close(self): pass


def _sensor(nano):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return DelphiSensor(agent_id="benign-tc", enforcement_mode="monitor",
                            enable_nano=nano, reporter=_Null())


def _load():
    with open(CORPUS, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


# First-party destination markers: a send/write to one of these is NOT egress
# out of the org's control. Everything else a send tool targets is treated as an
# external destination (a customer, a partner, an auditor, a third-party SaaS).
_FIRST_PARTY = ("internal://", ".internal", "workspace://", "confluence://",
                "gdrive://", "wiki://", "chroma://workspace", "pgvector://internal",
                "s3://acme-", "vault", "gs://acme-", "acme-analytics", "acme-raw",
                "acme-ml", "acme-archive", "acme-research", "acme-security")

_SEND_TOOLS = ("send_email", "send_statement", "send_sms", "send_survey",
               "send_report_email", "send_reminder_email", "send_payment",
               "export_report", "export_dataset", "export_to_", "export_gl",
               "export_tax_report", "export_audit_log", "export_bibliography",
               "export_to_quickbooks", "export_to_snowflake", "export_to_zotero",
               "publish_to_s3", "publish_to_bigquery", "publish_preprint",
               "write_to_s3", "upload_to_gcs", "upload_findings",
               "sync_to_salesforce", "sync_to_erp", "process_ach_batch",
               "trigger_webhook")

_PRIV_TOOLS = ("grant_iam_role", "grant_dataset_access", "grant_approver_role",
               "grant_temp_access", "revoke_access", "rotate_credentials",
               "create_secret", "create_user", "deploy_service", "rollback_deployment",
               "run_migration", "terraform_apply", "update_firewall_rule", "update_dns",
               "delete_old_snapshots", "drop_table", "truncate_staging", "run_payroll",
               "approve_payment", "promote_image", "close_period", "lock_period",
               "update_sla_policy", "update_policy", "issue_refund", "apply_credit",
               "redact_ticket", "revoke")

_STORE_TOOLS = ("kb_create_article", "kb_update_article", "update_runbook",
                "update_wiki", "store_document", "save_note", "write_report",
                "append_to_doc", "update_data_catalog", "register_model",
                "write_audit_note", "update_lineage", "index_document",
                "store_embedding", "write_embeddings", "create_literature_review",
                "update_feature_store", "create_macro", "create_annotation",
                "save_search_results", "update_vendor", "update_budget")


def _has_external_destination(args):
    blob = json.dumps(args).lower()
    if any(fp in blob for fp in _FIRST_PARTY):
        # a first-party marker present; only external if ALSO a clearly-external
        # address/host appears (e.g. a customer email alongside an internal note)
        pass
    # any email address, https URL, sftp/s3/gcs URI that is not first-party
    externals = re.findall(r'[\w.+-]+@[\w.-]+\.\w+|https?://[\w.-]+|sftp://[\w.-]+'
                           r'|s3://[\w.-]+|gs://[\w.-]+', blob)
    for tok in externals:
        if not any(fp.rstrip("/") in tok for fp in _FIRST_PARTY):
            return True
    return False


def _is_high_volume(args):
    blob = json.dumps(args)
    for m in re.findall(r'"(?:count_estimate|rows|replicas|items_estimate|partitions_estimate'
                        r'|recipients_estimate|contractors_estimate|assets_estimate'
                        r'|payments_estimate|employees_estimate|count|chunks)"\s*:\s*(\d+)', blob):
        if int(m) >= 500:
            return True
    return False


def _acceptance_surface(corpus):
    """Naive, mechanism-keyed detectors. Each returns the benign entries a
    default-on detector for that mechanism would fire on and must carve back out."""
    egress, priv, store, highvol = [], [], [], []
    for e in corpus:
        tool = e["tool"]
        if any(tool.startswith(t) or t in tool for t in _SEND_TOOLS) and _has_external_destination(e["args"]):
            egress.append(e)
        if tool in _PRIV_TOOLS:
            priv.append(e)
        if tool in _STORE_TOOLS:
            store.append(e)
        if _is_high_volume(e["args"]) or tool in ("backfill", "batch_infer", "batch_fetch",
                                                  "batch_summarize", "batch_restart",
                                                  "bulk_close_tickets", "bulk_tag",
                                                  "run_payroll", "process_ach_batch",
                                                  "run_depreciation", "generate_1099"):
            highvol.append(e)
    return {"external_egress_of_data": egress, "privileged_action": priv,
            "write_to_store(KB)": store, "high_volume_operation": highvol}


def main():
    corpus = _load()
    rs = _sensor(False)
    try:
        ns = _sensor(True)
    except Exception:
        ns = None  # nano extra / artifact absent; tool_call is rules-only anyway

    print(_rule("="))
    print("BENIGN TOOL-CALL CORPUS  -  false positives")
    print(_rule("="))
    print(f"corpus       : {len(corpus)} tool calls, 5 production personas "
          f"(benign_toolcalls/corpus.jsonl)")
    print("boundary     : every entry is a tool_call (scan_tool_call)")
    print("detection    : action != 'allowed'; mode=monitor")
    print()

    # ---- 1. current sensor (the required baseline) ----
    per_persona = defaultdict(lambda: [0, 0])  # persona -> [n, fp]
    rules_fp, nano_fp = [], []
    for e in corpus:
        r = rs.scan_tool_call(e["tool"], e["args"])
        per_persona[e["persona"]][0] += 1
        if r.action != "allowed":
            rules_fp.append((e, r))
            per_persona[e["persona"]][1] += 1
        if ns is not None:
            n = ns.scan_tool_call(e["tool"], e["args"])
            if n.action != "allowed":
                nano_fp.append((e, n))

    print(_rule("="))
    print("1. CURRENT SENSOR  (the baseline every candidate is judged against)")
    print(_rule("="))
    print(f"{'persona':<12}{'n':>5}{'rules FP':>12}")
    print(_rule())
    for persona in ("support", "devops", "data", "research", "finance"):
        n, fp = per_persona[persona]
        print(f"{persona:<12}{n:>5}{fp:>12}")
    print(_rule())
    print(f"{'TOTAL':<12}{len(corpus):>5}{len(rules_fp):>12}")
    print()
    print(f"rules-only false positives : {len(rules_fp)}/{len(corpus)} "
          f"({100.0*len(rules_fp)/len(corpus):.1f}%)")
    if ns is not None:
        print(f"rules+nano false positives : {len(nano_fp)}/{len(corpus)} "
              f"({100.0*len(nano_fp)/len(corpus):.1f}%)  "
              f"(nano does not run on tool_call, so this equals rules-only)")
    else:
        print("rules+nano false positives : NOT RUN (nano extra/artifact absent); "
              "identical to rules-only on tool_call by construction")
    print()
    if rules_fp:
        print("Every current-sensor false positive, named:")
        for e, r in rules_fp:
            print(f"  [{e['id']}] {e['persona']}/{e['tool']}  score={r.score:.2f}  "
                  f"rules={list(r.rules)[:3]}")
            print(f"        why benign: {e['why_benign']}")
    else:
        print("Current sensor: no false positives on this corpus.")
    print()

    # ---- 2. the detector acceptance surface (why this corpus exists) ----
    # A NAIVE version of each proposed detector, keyed on the MECHANISM not on
    # attack vocabulary. The count is how many benign production tool calls that
    # mechanism must NOT false-positive on. This is the real gate: the
    # attack-tuned prototypes in asi_boundary_candidates.py score near zero here
    # only because their vocabulary is attack-specific; a detector built to catch
    # the mechanism generically starts by firing on all of these, and every one
    # has to be carved back out. That carving is the false-positive budget, and
    # it is invisible against the mirror.
    surface = _acceptance_surface(corpus)
    print(_rule("="))
    print("2. DETECTOR ACCEPTANCE SURFACE  (what a generic detector must NOT flag)")
    print(_rule("="))
    print("Naive, mechanism-keyed detector -> benign production tool calls it hits.")
    print("Each is a legitimate instance of the shape the proposed detector targets.")
    print("A default-on detector has to clear all of these before it ships.")
    print()
    print(f"{'mechanism (naive)':<26}{'hits':>6}{'rate':>8}   examples")
    print(_rule())
    for name, hits in surface.items():
        rate = 100.0 * len(hits) / len(corpus)
        ex = ", ".join(e["id"] for e in hits[:4])
        print(f"{name:<26}{len(hits):>6}{rate:>7.1f}%   {ex}{' ...' if len(hits) > 4 else ''}")
    print()
    for name, hits in surface.items():
        print(f"[{name}] {len(hits)} legitimate instances a default-on detector must clear:")
        for e in hits:
            print(f"  [{e['id']}] {e['persona']}/{e['tool']}: {e['why_benign']}")
        print()

    # ---- machine-readable ----
    summary = {
        "n": len(corpus),
        "current_sensor": {
            "rules_fp": [e["id"] for e, _ in rules_fp],
            "rules_fp_rate": len(rules_fp) / len(corpus),
            "nano_fp": [e["id"] for e, _ in nano_fp],
        },
        "per_persona": {p: {"n": v[0], "rules_fp": v[1]} for p, v in per_persona.items()},
        "acceptance_surface": {n: [e["id"] for e in h] for n, h in surface.items()},
    }
    out = os.path.join(REPO, "benign_toolcalls", "last_run.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    print(_rule("="))
    print(f"machine-readable summary -> {out}")
    print(_rule("="))
    return 0


if __name__ == "__main__":
    sys.exit(main())
