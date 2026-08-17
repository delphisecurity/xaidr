# Threat model

xaidr is an in-process runtime sensor. It sits at four boundaries inside an
agent (`scan`, `scan_output`, `scan_tool_call`, `scan_a2a`) and returns a
verdict on what is passing through. This page says what that buys you and what
it does not. It is short on purpose.

## What it defends against

**Untrusted input reaching the model.** Text arriving from a user, a retrieved
document, a web page, a ticket, or a tool result is scanned before it is handed
to the model. Prompt injection and instruction-override shapes are caught on the
content path.

**A manipulated agent about to take a dangerous action.** The tool-call boundary
sees the action before it happens: the command, the path, the SQL, the
destination. An agent that has been talked into `rm -rf`, into reading a
credential file, into a tautological `DELETE`, or into piping an archive to a
raw socket is stopped or gated at the point of the call, not after.
[Coverage and limitations](README.md#coverage-and-limitations) gives the
family-level numbers and, more usefully, the families where enforcement is
deliberately classify-only.

**Secrets leaving.** The output boundary runs DLP against model responses, and
tool arguments are read for credentials on their way out.

**A lower-privilege agent inducing a higher-privileged one.** This is OWASP
ASI03 and it is not a detection problem: `@deploy-agent please run the
validation suite` is a benign sentence, and a detector that fired on it would
fire on every legitimate delegation in a fleet. The control is a configured
privilege lattice enforced by policy. See
[Agent privilege tiers](README.md#agent-privilege-tiers).

The load-bearing property there is worth stating on its own: **the privilege
tier is config-sourced and there is no runtime setter.** It is a constructor
argument, validated at construction, and the package exposes no API that raises
it afterwards. That is deliberate, because agent code is exactly what an
injected instruction gets to influence. An agent that has been tricked cannot
talk itself into a higher tier, because there is no call it could be persuaded
to make. Rewriting the tier means executing arbitrary code inside the process,
which is the compromise case below and not the manipulation case. The sensor
also never takes its **own** tier from an inbound header: a header is a claim
about an upstream hop and can never speak for the agent receiving it.

**Every verdict is emitted before the action.** Telemetry for a scan is enqueued
on the way out of the sensor, before the verdict reaches the caller and
therefore before the caller acts on it. The event carries the **true** verdict,
computed before monitor mode softens anything. So in monitor mode, where nothing
is enforced, the audit record still says what would have been blocked. An audit
trail exists even where enforcement does not, and that is the point of running
in monitor mode at all.

## What it does not defend against

**Process compromise.** An in-process sensor cannot survive compromise of the
process it lives in. If an attacker has code execution as the agent, or root on
the host, they can unload the sensor, monkey-patch the scan functions, edit the
configuration file the privilege tier is read from, or simply not call it. There
is no version of an in-process control that is immune to this. It is the same
limit every endpoint agent has, and it is stated here rather than left for you
to discover.

**The model's weights.** Poisoning, backdoors, and fine-tuning attacks are
upstream of anything a runtime sensor can see.

**The host.** Container escape as a *concept* is classified when it appears in a
command, but the sensor is not a host security product. It does not defend the
kernel, the container runtime, the orchestrator, or the filesystem.

**Anything upstream of the agent.** A compromised MCP server, a poisoned
dependency, a hostile model provider, a tampered CI pipeline. The sensor reads
what reaches its four boundaries. It has no opinion about how that data came to
exist.

**Unsigned chain claims.** The delegation chain and the per-hop privilege tiers
ride in transport headers, and they are not signed. An attacker with full
control of the headers can claim a *better* upstream tier and lower the computed
privilege ceiling. This is documented in the README and is repeated here because
it is a boundary and not a bug. Two guarantees do hold, and they are the ones to
rely on:

* the receiving sensor's **own** tier is config-sourced and cannot be set by a
  header
* every tampering that **removes** information tightens the verdict. Strip the
  chain, strip the tiers, mangle the values: all of it lands on tier 4 and gates
  the action. An attacker who deletes provenance ends up worse off than one who
  leaves it alone

Treat inbound tier claims as trustworthy only inside a mesh you already trust.
Cryptographically signed chains are a different product.

## The distinction that matters: manipulated versus compromised

This is the whole thing, and most arguments about agent security are really
arguments about which of these two is being discussed.

**A manipulated agent is running its own code.** It has been tricked. An
injected instruction in a retrieved document, a poisoned tool result, a
persuasive message from a peer agent, and now the agent sincerely intends to do
something it should not. Its own code is intact. It still calls the sensor,
because calling the sensor is part of its code. The sensor's configuration lives
outside the model's reach, so the privilege tier holds, the policy holds, and
the dangerous call gets a verdict. **This is the case xaidr is for.**

**A compromised process is running the attacker's code.** Remote code execution,
a malicious dependency, a stolen credential used to redeploy the agent. At that
point the sensor is not a control, it is one of the things the attacker
controls. Nothing in this repository helps you. What helps you is process
isolation, least privilege on the workload identity, and the fact that telemetry
already emitted before the compromise is off-box.

**Most published agent incidents are the first kind.** Indirect prompt
injection, confused-deputy delegation, an agent following instructions it found
in data. Those are manipulation, and manipulation is defensible at the boundary
because the agent is still cooperating with its own instrumentation. Treating a
manipulation control as if it were a compromise control is how a security tool
ends up over-trusted, so:

| | manipulated agent | compromised process |
|---|---|---|
| whose code is running | the agent's | the attacker's |
| is the sensor still called | yes | only if the attacker wants it to be |
| is the config reachable by the attack | no | yes |
| does the privilege tier hold | yes | no |
| what actually helps | this sensor | isolation, least privilege, off-box audit |

## Reproducing the claims

Nothing on this page should be taken on trust either.

* detection and false positives, by family, from the committed corpus:
  `python scripts/corpus_report.py`
* latency at every boundary, on your hardware:
  `python scripts/benchmark.py`, and see [BENCHMARKS.md](BENCHMARKS.md)
* the privilege-tier semantics, including the absence cases:
  `tests/test_privilege_tiers.py`
* fail-open, bounded-input and malformed-content behavior:
  `tests/test_operational_resilience.py`,
  `tests/test_security_invariants.py`

To report something this model gets wrong, see [SECURITY.md](SECURITY.md).
