"""STEP 1: reproduce F2, F3, F4, F6 against main. No fixes."""
import json, sqlite3, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import xaidr
from xaidr import Sensor

print(f"xaidr {xaidr.__version__}  {xaidr.__file__}\n")


class N:
    def report(self, *a, **k): pass
    def emit(self, *a, **k): pass
    def flush(self, *a, **k): pass
    def close(self, *a, **k): pass


def sensor(policy=None, **kw):
    s = Sensor(agent_id="repro", enforcement_mode="block", reporter=N(), **kw)
    if policy:
        assert s.set_policy(policy) is True, "policy rejected"
    return s


def pol(match, effect):
    return {"version": "1", "defaults": {"effect": "allow", "unclassified": "allow"},
            "rules": [{"id": "gate", "effect": effect, "match": match}]}


# ══════════════════════════════════════════════════════════════════
print("=" * 76)
print("F2  positional calling bypasses a loaded structural policy")
print("=" * 76)
TERRAFORM = "terraform destroy -auto-approve"
ran = []


def run_command(command):
    ran.append(command)
    return "executed"


s = sensor(pol({"impact_class": ["infra_destruction"]}, "require_approval"))
protected, = s.protect_tools([run_command])

ran.clear()
kw_out = protected(command=TERRAFORM)
kw_ran = list(ran)
ran.clear()
pos_out = protected(TERRAFORM)
pos_ran = list(ran)

print(f"  keyword    run_command(command=...) executions={len(kw_ran)}  -> {str(kw_out)[:56]}")
print(f"  positional run_command(...)         executions={len(pos_ran)}  -> {str(pos_out)[:56]}")
print(f"  VERDICT: {'REPRODUCED' if len(pos_ran) == 1 and len(kw_ran) == 0 else 'did not reproduce'}")
print(f"  (what the scan sees) keyword  : {s.scan_tool_call('run_command', {'command': TERRAFORM}).action}")
print(f"  (what the scan sees) positional: {s.scan_tool_call('run_command', {'arg0': TERRAFORM}).action}")

# ══════════════════════════════════════════════════════════════════
print()
print("=" * 76)
print("F3  first-argument-wins hides later dangerous values")
print("=" * 76)
s3 = sensor()
SQL_BAD = "DELETE FROM records WHERE 1=1"
META = "https://2852039166/latest/meta-data/iam/security-credentials/"

cases = [
    ("SQL benign-first", {"first": "SELECT 1", "query": SQL_BAD}),
    ("SQL danger-first", {"query": SQL_BAD, "first": "SELECT 1"}),
    ("URL benign-first", {"first": "https://example.com/docs", "url": META}),
    ("URL danger-first", {"url": META, "first": "https://example.com/docs"}),
]
for label, args in cases:
    r = s3.scan_tool_call("db_or_http", args)
    print(f"  {label:18} keys={list(args)}  -> {r.action:8} {r.score:.2f} {r.rules[:2]}")
print("  VERDICT: REPRODUCED if the two orders of the same pair differ")

# ══════════════════════════════════════════════════════════════════
print()
print("=" * 76)
print("F4  SQL lexical unsoundness, against a real SQLite oracle")
print("=" * 76)


def oracle(stmt):
    """Execute against a disposable 3-row in-memory DB. Returns rows remaining."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, note TEXT)")
    db.executemany("INSERT INTO records VALUES (?,?)",
                   [(1, "a"), (7, "b"), (9, "c")])
    db.commit()
    try:
        db.executescript(stmt)
        db.commit()
    except Exception as exc:
        return f"sqlite-error: {type(exc).__name__}"
    return db.execute("SELECT COUNT(*) FROM records").fetchone()[0]


s4 = sensor(pol({"impact_tier": ["critical"]}, "require_approval"))
BYPASS = [
    "DELETE FROM records RETURNING 'where id=7'",
    "WITH x AS (SELECT 1) DELETE FROM records",
    "SELECT '--'; DELETE FROM records WHERE 1=1",
]
FP = [
    "DELETE FROM records WHERE note='1=1'",
    "DELETE FROM records WHERE id=7 AND 1=1",
]
print("  BYPASSES (should gate; deletes everything):")
for stmt in BYPASS:
    r = s4.scan_tool_call("run_sql", {"query": stmt})
    left = oracle(stmt)
    print(f"    {r.action:17} {r.score:.2f} rows_left={left!s:16} {stmt[:46]}")
print("  FALSE POSITIVES (should not gate; deletes 0 or 1 row):")
for stmt in FP:
    r = s4.scan_tool_call("run_sql", {"query": stmt})
    left = oracle(stmt)
    print(f"    {r.action:17} {r.score:.2f} rows_left={left!s:16} {stmt[:46]}")
print("  (control: the plain form the policy is meant to gate)")
stmt = "DELETE FROM records"
r = s4.scan_tool_call("run_sql", {"query": stmt})
print(f"    {r.action:17} {r.score:.2f} rows_left={oracle(stmt)!s:16} {stmt}")

# ══════════════════════════════════════════════════════════════════
print()
print("=" * 76)
print("F6  lost provenance relaxes delegation policy")
print("=" * 76)
from xaidr import inject_context, extract_context, clear_flow, begin_flow

DEPLOY = {"env": "production"}
POLICY6 = {"version": "1", "defaults": {"effect": "allow", "unclassified": "allow"},
           "rules": [{"id": "tier-gate", "effect": "require_approval",
                      "match": {"tools": ["deploy_prod"]},
                      "conditions": {"min_chain_tier_above": 2}}]}


def make_headers():
    """A tier-4 sender delegating to a tier-1 receiver."""
    clear_flow()
    snd = Sensor(agent_id="sender", enforcement_mode="block", reporter=N(),
                 privilege_tier=4)
    begin_flow(principal="alice")
    snd.scan("please deploy", direction="input")
    h = inject_context()
    clear_flow()
    return h


HEADERS = make_headers()
print(f"  headers: {sorted(HEADERS)}")
print(f"    chain = {HEADERS['x-openA2A-chain']!r}   tiers = {HEADERS['x-openA2A-tiers']!r}")
print()


def receiver(headers, label):
    clear_flow()
    recv = Sensor(agent_id="recv", enforcement_mode="block", reporter=N(),
                  privilege_tier=1)
    assert recv.set_policy(POLICY6) is True
    ok = extract_context(headers)
    lp = recv._least_privileged_tier()
    action = recv.scan_tool_call("deploy_prod", DEPLOY).action
    print(f"  {label:32} extract={ok!s:6} least_priv={lp!s:5} -> {action}")
    clear_flow()
    return action


receiver(dict(HEADERS), "valid headers (CONTROL)")
receiver({k: v for k, v in HEADERS.items() if "tiers" not in k.lower()},
         "tier claims stripped")
receiver({}, "ALL headers stripped")
receiver({k: v for k, v in HEADERS.items() if "correlation" not in k.lower()
          and k.lower() != "traceparent"}, "correlation stripped")

print()
print("  ThreadPoolExecutor handoff after a valid extraction:")
from concurrent.futures import ThreadPoolExecutor
import contextvars

clear_flow()
recv = Sensor(agent_id="recv", enforcement_mode="block", reporter=N(), privilege_tier=1)
recv.set_policy(POLICY6)
extract_context(dict(HEADERS))
inline = recv.scan_tool_call("deploy_prod", DEPLOY).action
with ThreadPoolExecutor(max_workers=1) as ex:
    in_thread = ex.submit(lambda: recv.scan_tool_call("deploy_prod", DEPLOY).action).result()
ctx = contextvars.copy_context()
with ThreadPoolExecutor(max_workers=1) as ex:
    with_ctx = ex.submit(lambda: ctx.run(
        lambda: recv.scan_tool_call("deploy_prod", DEPLOY).action)).result()
clear_flow()
print(f"    inline                   -> {inline}")
print(f"    plain ThreadPoolExecutor -> {in_thread}")
print(f"    copy_context().run       -> {with_ctx}")
