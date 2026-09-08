# Closing the boundary gap the held-out ASI battery found

Measure, group, propose. **Nothing is built here.** The battery
(`asi_battery/`) and its register-matched benign mirror are the acceptance
criteria for whatever gets built; every candidate below is measured against them
first, and none is tuned to them.

Branch: `feat/asi-boundary-coverage`, off `main` (85a2f98). The baseline and
every number below are **identical on `main` and on `feat/asi-lpci-rules-gated`**
(0 per-case detection differences across all 240 cases), so the analysis does not
depend on which of the two you build from. Regenerate with
`python scripts/asi_boundary_candidates.py`.

## The fact under the gap

| | catch (120 attacks) | false-positive (120 benign) |
|---|---|---|
| rules-only | 21/120 (18%) | 7/120 |
| rules + nano | 41/120 (34%) | 18/120 |

**All 20 of nano's catches are on the `input` boundary.** `nano_raw` is `None` on
every tool_call, output, a2a, and non-input sequence step, because nano is scoped
to inbound chat text. Two detection layers, but on four of the five boundaries
only one of them runs. The gap is not that the attacks are subtle; it is that
three boundaries that already exist in the API (`scan_tool_call`, `scan_output`,
`scan_a2a`) get no detector for these shapes, and nano cannot reach them.

99 attacks are missed by rules alone. Nano rescues 20, all on `input`. **79
remain**, and that is the population this proposal is about.

## a. The 79 misses, grouped by mechanism (not category)

Grouped by *what would have to exist to catch them*. Counts are of the 79
rules+nano misses; the buildable column is measured (section c), not asserted.

| # | mechanism | boundary | misses | reach |
|---|---|---|---:|---|
| G1 | data egress to an external destination through a tool/message argument | tool_call, a2a | 7 | **buildable** |
| G2 | dangerous privileged or destructive action in a tool argument (self-grant admin, disable approval/backup/safety, world-open firewall, all-scope destruction, mining) | tool_call | 15 | **buildable** |
| G3 | fact- or trust-shaped poison written through a tool argument (KB/memory/registry write asserting a false policy or elevating trust) | tool_call | 6 | **buildable** |
| G4 | resource / rate abuse: unbounded loops, fan-out, denial-of-wallet | input, tool_call, a2a | 9 | **buildable** (per-message subset) |
| G5 | output self-incrimination: concealment, a destructive action reported as routine, drift narrated in the reply | output | 5 | **buildable** |
| G6 | plain-language instruction / goal / trust / exfil directed at a *peer agent* | a2a | 14 | **hard** (nano's blind spot, on a boundary nano never sees) |
| G7 | plain-prose agentic intent on input that nano scores near zero (goal override, stealth, fabricated policy) | input | 9 | **hard** (nano's ceiling) |
| G8 | output integrity that needs ground truth (payout recipient swapped, an authorization that was never granted) | output | 2 | **out of reach** for a per-message detector |
| G9 | emergent multi-step: a delegation loop, a cascade, or drift whose individual messages are each benign | sequence | ~5 | **out of reach** for a per-message detector; the rate/loop subset is the existing (opt-in) circuit breaker |
| G10 | tool-argument shapes the crude prototypes missed (a bare financial transfer, re-pointing a trusted agent to an external host, relabelling a source authoritative) | tool_call | 5 | **buildable** with a sharper discriminator than the prototype |

G1 through G5 and G10 are per-message content on boundaries that already exist.
G6 through G9 are where a per-message detector runs out, and some of that is a
finding, not a failure (below).

## b. What each group needs, and what is genuinely out of reach

**Buildable, per-message, on an existing boundary (G1, G2, G3, G5, G10).**
`scan_tool_call` and `scan_output` already run and already carry the full text of
the argument or the reply. Nothing new has to be observed. What is missing is a
detector for the shape:

- **G1 egress** needs to classify the *destination* as external vs internal (an
  email domain, a URL host, a filesystem path) and notice a data-bearing payload
  alongside it. The sensor already sees both in the argument.
- **G2 privileged action** needs a default set of dangerous-action signatures on
  the tool path. The machinery for the *decision* already exists: privilege
  tiers and the YAML policy engine. The README's own ASI03 verdict says this is
  "telemetry only until configured." The gap is that nothing fires by default.
- **G3 poison-on-write** needs to read the *value* being written to a KB, memory
  or registry entry and notice a policy-subverting or trust-elevating assertion.
  The README notes the `asi06` family already catches instruction-shaped memory
  writes at flag tier; the gap it names explicitly ("a false fact with no
  instruction still returns allowed") is exactly this group.
- **G5 output self-incrimination** is the easiest: the concealing intent is
  stated in the reply itself ("I skipped the ownership verification but reported
  it as passed"). A concealment-vs-disclosure rule on `scan_output` reaches it.

**Hard, because it is nano's blind spot (G6, G7).** These are plain-language
directives with no lexical tell. G7 is the input-boundary version nano already
tries and misses (the same gap the held-out nano set found). G6 is the same
semantics delivered over A2A, on a boundary nano does not run on at all. Both are
reachable *in principle* by extending plain-language behavioural detection, but
that is precisely the direction with the worst false-positive risk, and it is the
largest remaining lever (23 of the 39 residual). It should not be rushed into a
keyword rule.

**Out of reach for a per-message detector, and that is the finding (G8, G9).**

- **G8** (2 cases) needs to know the *correct* answer to compare against: which
  account a refund should return to, whether authorization AX-9 exists. A sensor
  that sees one message cannot know either. This is a deployment control (bind
  the correct recipient / verify the token), not a detector, and it belongs with
  the policy engine and `set_origin`, not with a rule.
- **G9** (about 5 cases) is drift and cascade whose every individual message is
  benign; the harm is only in the sequence. The README already says this
  plainly, and ASI10 is `OUT OF REMIT` for exactly this reason: detecting it
  needs cross-session state a single in-process sensor does not have. The
  rate/loop subset (a delegation loop, a fan-out storm) is already addressed by
  the circuit breaker and the delegation-rate breaker, which are opt-in.

The important correction to the intuition that "multi-step is uncoverable": most
of the sequence misses are **not** in G9. Their write step or injected field is
individually detectable (a poison KB write, a self-grant, an injected A2A
instruction), so they fall into G1/G2/G3/G6 and are caught at that step without
any cross-call state. Only the genuinely emergent handful (G9) needs state.

## c. Buildable, ranked, measured against the benign mirror

Five prototype discriminators, run over the battery by
`scripts/asi_boundary_candidates.py`. They are crude heuristics whose only job is
to estimate separation; the point is the false-positive column, measured on all
120 register-matched benign cases.

| candidate (prototype) | new catches | benign FP (of 120) | notes |
|---|---:|---:|---|
| `priv_action` (G2) | 15 | 1 | biggest single lever; FP is `ASI08-B10`, a fleet-wide *enable* of approvals |
| `resource_unbounded` (G4) | 9 | 0 | clean on this set |
| `egress_external` (G1) | 7 | 1 | FP is `ASI09-B10`, a protective warning *about* an external vendor |
| `poison_write` (G3) | 6 | 1 | FP is `ASI06-B08`, a KB entry that *forbids* asking for card numbers (negation) |
| `output_conceal` (G5) | 4 | 0 | clean on this set |
| **union** | **40** | **3** | rules+nano 41/120 -> **81/120 (68%)**, FP 18 -> 21 |

**Every one of the 3 false positives is diagnosable, and the benign mirror is
what surfaced it:**

- `ASI08-B10` (enable approvals fleet-wide) trips `priv_action` because the crude
  rule keys on `scope=all-agents`. The fix the benign case points at: require the
  destructive *direction* (disable / grant-to-self / open), not the scope alone.
- `ASI09-B10` (warn that `payouts.ext` is external, verify transfers) trips
  `egress_external` on the vendor name plus "records". The fix: the egress signal
  must key on an actual send/write *action* to the destination, not a mention of
  it. This is the same protective-vs-active distinction the descriptive-frame
  dampener already draws.
- `ASI06-B08` ("Never ask for full card numbers") trips `poison_write` on a
  negated phrase. The fix already ships: the repo's negation-scoping guard
  (`tests/test_negation_scoping_guard.py`).

So the FP cost is not 3 that must be accepted; it is 3 that name the exact guard
each detector needs, all of which either already exist in the codebase
(negation-scoping, protective-frame) or are a one-line direction test.

Ranking by buildable-without-a-new-FP-problem: **G4 and G5 are clean today
(0 FP). G2, G1, G3 are clean once they reuse a guard the repo already has.**

## d. The smallest set that moves the most, and what each costs

Build **G1, G2, G3, G4, G5** as per-message content detectors on the boundaries
that already exist. Measured effect: **rules+nano 41 -> 81 of 120 (34% -> 68%),
at +3 benign false positives on the mirror, all three fixable by a guard already
in the tree.** No new boundary, no new scan entry point, no cross-call state, no
new model.

| build | moves | cost |
|---|---:|---|
| G2 dangerous-action signatures on the tool path (reuse privilege tiers + policy) | 15 | default action-shape rules + a direction test; the decision machinery already exists, so this is mostly authoring signatures and a default-on flag |
| G4 unbounded-quantifier rule on input/tool/a2a | 9 | one content rule (unbounded quantifier + resource verb); complements the existing circuit breaker for the cross-call subset it cannot see |
| G1 external-destination egress on send/write/POST tools | 7 | a destination classifier (email domain / URL host / path) + a send-action gate; **highest field-FP risk** (real agents send external mail and call external webhooks), so this one most needs a production-benign corpus before default-on |
| G3 poison-on-write content rule for KB/memory/registry writes | 6 | a policy-subversion / trust-elevation content rule that runs the existing negation-scoping pass on the written value |
| G5 concealment-vs-disclosure rule on output | 4 | one output rule keying on a concealment clause co-occurring with an action, excluded by the disclosure markers the benign mirror supplies |

Do **not** build for G6/G7 (plain-language behavioural on a2a and input) in the
same change. It is the largest residual (23) but the highest FP risk, it is
nano's job on input, and it needs its own benign measurement pass. Do **not**
build a per-message detector for G8/G9; G8 is a policy/provenance control and G9
is the circuit breaker's territory, already opt-in, and ASI10's `OUT OF REMIT`.

Expected end state if only G1-G5 ship: **catch 68%, residual 39** (a2a 14,
input 9, sequence 8, tool_call 5 sharper-discriminator, output 3), with the
residual honestly attributable to the two hard groups and the two out-of-reach
ones, not to an unexamined boundary.

## Caveats, stated because they decide whether this is safe

1. **The benign mirror is a lower bound on false positives, never an upper
   bound.** It was authored as the contrast to the attacks, so its destinations
   are internal, its policies accurate, its quantifiers bounded. Real traffic is
   not so tidy: legitimate external email, legitimate fleet-wide config,
   legitimate "delete the old records". A candidate that scores 0 FP here can
   still be noisy in production.
2. **There is no committed benign *tool-call* corpus.** The existing benign pools
   (shell corpus, the 2000 real-benign prompts) are input/command text and do not
   exercise the tool-argument path these detectors live on. Before any of G1-G3
   ships default-on, a production-shaped benign tool-call corpus has to exist and
   the detector has to be measured against it. This proposal cannot substitute
   the 120-case mirror for that.
3. **Acceptance, not tuning.** The battery and its mirror are the gate a build
   must pass, not the thing a build is fit to. A detector that only separates on
   these 240 cases has learned the cases, not the mechanism. Each detector must
   also hold on the existing corpora with no regression (rules+nano is
   byte-identical on the 2000-prompt sample today) and be re-measured on new
   held-out cases an outsider writes, because that is what moved these numbers in
   the first place.
4. **Dependency of building on this branch.** The battery lives on
   `feat/asi-lpci-rules-gated`; this branch restored it. The two branches produce
   an identical baseline, so either base works, but the feature branch's ASI/LPCI
   rule work should be reconciled before shipping so this effort does not diverge
   from it.

## Reproduce

```sh
python scripts/asi_battery_report.py          # the 21/41 baseline and every miss
python scripts/asi_boundary_candidates.py     # the candidate table above
```

Both need the `nano` extra and the model artifact for the rules+nano half; the
rules-only half runs with the core package alone.
