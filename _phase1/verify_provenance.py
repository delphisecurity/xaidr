import time
from xaidr import Sensor, begin_flow, clear_flow
from xaidr.schema import to_openA2A

class Cap:
    def __init__(self): self.events=[]
    def report(self,b): self.events.extend(b)
    def close(self): pass

def wait_events(cap, n, timeout=5.0):
    # Deterministically wait for all N expected events to be delivered. Each
    # Sensor runs its OWN background telemetry thread, so a fixed sleep() may read
    # before the events are flushed. Events arrive within milliseconds, so this
    # returns fast — it just removes the race.
    t0=time.time()
    while len(cap.events) < n and time.time()-t0 < timeout:
        time.sleep(0.005)
    assert len(cap.events) >= n, f"only {len(cap.events)}/{n} events delivered"
    return cap.events

def event_for(cap, agent_id):
    # Select an event by agentId — NOT by list position. Multiple sensors deliver
    # to a shared reporter from independent threads, so delivery ORDER (and thus
    # cap.events[-1]) is nondeterministic; only the per-agent event content is.
    evs=[e for e in cap.events if e["data"]["agentId"]==agent_id]
    assert evs, f"no event for {agent_id}; saw {[e['data']['agentId'] for e in cap.events]}"
    return evs[-1]

def chain_of(m):
    dc=m["gen_ai.security.provenance.delegation_chain"]
    return [h["agent_id"] for h in dc]

# 1 + 3: NO flow -> NO provenance, and no leakage across unrelated scans
clear_flow()
cap=Cap(); s=Sensor(agent_id="solo", reporter=cap)
s.scan("hello one"); s.scan("hello two"); s.scan("hello three")
wait_events(cap, 3)
for e in cap.events:
    m=to_openA2A(e)
    prov=[k for k in m if "provenance" in k]
    assert not prov, f"FAIL: provenance fabricated with no flow: {prov}"
print("1+3 ok: no flow -> no provenance, no cross-scan leak")

# 2 + 4: a real flow works and is correct
clear_flow()
cap2=Cap()
begin_flow(principal="user:alice")
a=Sensor(agent_id="agent-a", reporter=cap2)
b=Sensor(agent_id="agent-b", reporter=cap2)
a.scan("route this"); b.scan("process this")
wait_events(cap2, 2)
last=to_openA2A(event_for(cap2, "agent-b"))   # select agent-b's event, not events[-1]
assert last.get("gen_ai.security.provenance.on_behalf_of")=="user:alice", last
chain=chain_of(last)
assert chain==["user:alice","agent-a","agent-b"], chain
print("2 ok: active flow emits correct chain", chain)

# 4: a fresh flow does not inherit the previous chain
clear_flow()
cap3=Cap()
begin_flow(principal="user:bob")
c=Sensor(agent_id="agent-c", reporter=cap3)
c.scan("new flow")
wait_events(cap3, 1)
last3=to_openA2A(event_for(cap3, "agent-c"))
chain3=chain_of(last3)
assert chain3==["user:bob","agent-c"], f"FAIL: new flow inherited old chain: {chain3}"
print("4 ok: fresh flow isolated", chain3)

print("\nALL PROVENANCE EXIT CONDITIONS MET")
