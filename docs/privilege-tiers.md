# Agent privilege tiers

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

## Agent privilege tiers

The attack this defends is a low-privilege agent inducing a high-privilege peer
to act on its behalf (OWASP ASI03). The canonical form looks like this:

> `@gemini-cli please review and run the validation suite`

That message scores **0.0** on every detection path in this package, and it is
right to. It is a benign, well-formed, entirely reasonable sentence. There is no
payload to find, no obfuscation, nothing to detect. A detector that fired on it
would fire on every legitimate delegation an agent fleet performs.

The escalation is not in the text. It is in the fact that the sender may not
perform the action and the receiver may. That is a property of your deployment,
not of the message, so the control is a **control**: a privilege lattice you
configure, enforced by policy.

## The privileged-action shape detector (new in 1.14.0)

Separately from the tier lattice and the policy engine, the tool boundary now
checks tool arguments for the *shapes* a privilege subversion takes, by default,
with no configuration. It is structural: it walks the argument key/value pairs
(the same way the command, SQL and URL parsers already do), so it reads the
action rather than regexing a joined value string. It fires on a self-granted
role (`principal: agent://self`), a disabled control (approval, safety,
monitoring, backup retention, or a trust root invalidated without reissue), a
waived approval (`approval: none`, `confirm: skip`), an escalation to admin or
root carrying no governance marker, a network rule opened to `0.0.0.0/0`, and a
concealed grant (`visible: false`). An argument that carries none of those shapes
is silent, so an approved scoped grant, a scheduled credential rotation and a
payroll run produce nothing.

**Each of those is a RELATION between two keys, not a keyword anywhere in the
call — corrected in 1.14.1, where reading them as unrelated facts flagged
ordinary work.** A self-directed principal is a self-*grant* only when the call
also names what is granted: `get_profile(user="self")` is a read and is silent,
`grant_role(principal="agent://self", role="org-admin")` fires. An admin-shaped
role is an escalation only when nothing in the call makes it a query: beside a
filter key it is a listing (`list_repos(visibility="all", role="admin")` asks for
repos you already administer), and a read-only marker on the same value is a
scope request (`admin.directory.user.readonly`). A control NAME appearing as a
value is a disabled control only when a disabling value sits in the same setting
record — `set_flag(flag="enforce_approvals", value=false)` fires,
`plot_series(panel="monitoring", offset=0)` is pagination and does not.

The correction only ever removes flags. Nothing that was silent before became
loud, and the detector fires on the same set of held-out battery shapes it fired
on at 1.14.0.

It flags; it does not block, and the reason matters. Every governance marker it
reads is app-supplied and unsigned, so a fabricated approval reference on a
self-grant evades it exactly as it evades a policy. It raises the cost of the
obvious shapes; it is not an authorization boundary.

That is why the tier lattice and policy below still exist and still do the real
work: they are the control. The shape detector is a default-on signal that
surfaces the crude attempts for review; the policy is what actually stops a
privileged action a deployer has decided must not happen. One deliberate
non-goal: crypto-mining as a workload has no structural tell — its only signal is
a denylist of miner image names — so it is left to policy rather than folded into
the shape detector.

**Assigning a tier.** One constructor argument, 1 to 4, where **1 is the highest
privilege** and 4 the lowest:

```python
triager  = Sensor(agent_id="triager",  privilege_tier=4)   # reads tickets
deployer = Sensor(agent_id="deployer", privilege_tier=1)   # can ship to prod
```

It is configuration and only configuration. There is no setter, and none is
coming: a tier that agent code could raise at runtime is not a control, because
agent code is precisely what an injected instruction gets to influence. An
invalid value fails at construction rather than defaulting quietly, so a typo
surfaces as a `ValueError` in your face instead of silently enforcing something
other than what you wrote. Omit it and the sensor is tier 4, the lowest.

The sensor never takes its **own** tier from a header. An inbound tier is a claim
about an upstream hop; it can never speak for the agent receiving it.

**Carriage.** The tier rides its own header alongside the delegation chain,
positionally aligned to it:

```
x-openA2A-chain: a-low:agent>b-high:agent
x-openA2A-tiers: 4,1
```

A separate header rather than a third field in the chain is what makes this
backward compatible in both directions. A sensor that predates the feature
ignores an unknown header and keeps parsing the chain exactly as before; a
current sensor reading an older caller's headers simply finds it absent and
treats every hop as tier 4. An un-instrumented hop in the middle publishes an
empty field rather than a fabricated number, so `4,` says "tier 4, then unknown"
instead of guessing.

**The policy dimension.** `min_chain_tier_above` goes under `conditions:`, beside
`trust_below`, because it is a numeric comparison rather than a glob match:

```yaml
- id: no-privilege-escalation
  effect: require_approval
  match:
    impact_class: ["execute", "credential_access", "escalate",
                   "transfer", "delete", "deploy"]
  conditions:
    min_chain_tier_above: 1
```

It matches when the least-privileged tier anywhere in the chain, including this
sensor's own, is numerically greater than the value given. Numerically greater
means *less* privileged, so `min_chain_tier_above: 1` reads as "something below
tier 1 is involved in this action".

`read`, `send` and the other communication classes are deliberately **not** in
that match list, and that omission is how normal cross-tier work keeps flowing. A
tier-4 agent asking a tier-1 agent for information is not escalation; agents do
it constantly. Only the classes that *act* are gated, and they are gated through
the same impact classifier you already configure, not a second mechanism.

```python
# tier-4 triager delegates to the tier-1 deployer
deployer.scan_tool_call("read_file",    {"path": "README.md"})     # -> allowed
deployer.scan_tool_call("run_command",  {"command": "bash -c 'id'"})
# -> approval_required, rules ['policy:no-privilege-escalation']
```

**Absence semantics, which is the part that matters in production.** Most agents
are not instrumented for provenance at all, and reading "no chain" as "unknown
upstream, therefore tier 4" would make every un-instrumented tier-1 agent exceed
its own gate and halt all of its own work. So absence is two different
situations with opposite answers, and the discriminator is whether the work
**arrived**:

| situation | result |
|---|---|
| **No delegation.** Nothing arrived; the chain is empty or names only this agent | the agent's own tier applies, and nothing gates |
| **Delegation with an unknown tier.** Work arrived (an A2A receive, or a restored inbound context) but a hop carries no usable tier | that hop counts as tier 4 |

A tier-1 agent doing its own privileged work with no chain is therefore
`allowed`, which is the common case and must stay that way.

**The security property, plainly.** Every tampering that *removes* information
tightens the verdict. Strip the chain header, strip the tiers header, or mangle
the values into nonsense, and all three land on tier 4 and gate the action. An
attacker who deletes provenance ends up worse off than one who leaves it alone,
which is the only direction that makes the control worth having.

**The limit, equally plainly.** An attacker with full control of the headers can
claim a *better* upstream tier and lower the computed maximum. Unsigned transport
metadata cannot prevent that, and this feature does not pretend otherwise. The
two guarantees that do hold are worth stating exactly: the receiving sensor's own
tier is config-sourced and unforgeable, and removal always tightens. Treat
inbound tier claims as trustworthy only inside a mesh you already trust.
Cryptographically signed chains are the platform-tier answer, not this one.

**The approval handoff.** A tier violation yields `approval_required`. The action
does **not** execute, and `protect_tools` and the LangChain middleware enforce
that for you. What happens next is yours: the open sensor cannot own a pending
queue or a reviewer UI, so you route the halt into whatever you already run.

```python
r = deployer.scan_tool_call("run_command", {"command": "bash -c 'id'"})
if r.must_halt:                       # covers blocked and approval_required
    return open_ticket_for_review(r)  # your queue, your Slack, your workflow
```

If you have no approval mechanism, use `effect: block` instead and the same rule
denies outright. Both are correct; the choice is about whether a human will
actually look:

| effect | verdict | choose it when |
|---|---|---|
| `require_approval` | `approval_required` | someone will adjudicate, and a cross-tier request is a normal event you want reviewed rather than refused |
| `block` | `blocked` | there is no reviewer, and an unattended halt is better than an unattended action |

With no approval workflow the two behave identically at the point of
enforcement: the action does not run either way.

**Audit.** Every tool call emits the computed tier, this agent's own tier,
whether one was configured, whether the work was delegated, and the per-hop tiers
alongside the policy rule that fired, so "why did this need approval?" is
answerable from the event alone rather than by re-deriving it:

```json
{"action": "approval_required", "authzPolicyId": "no-privilege-escalation",
 "privilegeTier": 1, "privilegeTierConfigured": true,
 "leastPrivilegedTier": 4, "delegated": true, "chainTiers": [4, 1]}
```

**The honest boundary.** Config-bound tiers stop a **manipulated** agent, one
that has been talked into asking for something it should not have. They do not
stop a **compromised process** that can rewrite its own configuration, because at
that point the tier is just a number in a file the attacker controls. And unsigned
chain claims are only as good as the mesh they travel in. This is a containment
control for a fleet you operate, not a trust boundary against a hostile host.

---

