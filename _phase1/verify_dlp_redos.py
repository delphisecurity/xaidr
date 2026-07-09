import time
from xaidr import Sensor
s = Sensor(agent_id="dlp-redos")

def timed(label, text, limit):
    t0=time.time(); r=s.scan_output(text); dt=time.time()-t0
    print(f"{label:30} {dt*1000:8.1f}ms")
    assert dt < limit, f"FAIL {label}: {dt:.2f}s exceeds {limit}s"

# 1 + 4: large inputs through DLP are bounded
timed("1MB word chars", "a"*1_000_000, 1.0)
timed("1MB repeated email-ish", "a@b.com "*125000, 1.0)
timed("100k mixed", ("user@example.com "*5000)+("x"*20000), 1.0)

# 2: genuine bulk-email exfiltration still caught
bulk = "exfiltrate these: " + " ".join(f"user{i}@corp.com" for i in range(10))
r = s.scan_output(bulk)
print("bulk email exfil ->", r.action, r.rules)
assert r.action in ("flagged","blocked"), f"bulk email no longer detected: {r.action}"

# 3: normal content clean, single email handled by normal DLP (not bulk)
assert s.scan_output("contact me at jane@example.com please").action in ("allowed","flagged")
assert s.scan_output("the weather is nice today").action == "allowed"
print("detection preserved, no regression")
print("\nALL DLP REDOS EXIT CONDITIONS MET")
