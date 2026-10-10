# A2 — value-origin seam wiring. BRIEF

## Goal
Wire the A1 value-origin core into the sensor's real seams so a destination named
by untrusted content is caught at the tool call. Today nothing calls the core:
A1 is proven only from inside the process.

## Base
`feat/value-origin-seams` from `origin/main` at `25dc9de` (the A1 merge commit,
CI green). `25dc9de` is also A1's pin for the chassis.

## Settled before this build (do not relitigate)
- The four W1 rulings, applied in #33 and merged: each parsed part of a
  mailbox-list yields its own finding; percent-decoding before UTS-46;
  URL_PREFIX refuses `.` and `..`; V-19 accepts special schemes without `//`
  and bare dotted quads with a path.
- `docs/value-origin-rulings.md` wins wherever it differs from the spec.
- Build decisions in that doc, accepted: unbalanced quoting counts as junk; a
  saturated ledger reports `ledger_saturated`; R4 also covers a bare port,
  query, fragment and bracketed IPv6 after the address.
- Open positioning: this is the action layer. No open/paid parity work. No text
  false-positive whack-a-mole.

## Out of scope
- Anything in paid, the Brain or the chassis.
- The four metadata-endpoint integer spellings still carrying strict xfails
  (`0xA9FEA9FE`, decimal, octal, mixed). Follow-up, not A2.
- Any new network surface. Nothing is sent anywhere new.

## Scope
1. Wire the core into these seams: principal input recording; tool-result
   recording (`direction="tool_result"`, the seam #26 added); tool-call argument
   evaluation; hops and delegation (`record_hop`, `begin_flow`,
   `extract_context`).
2. Move `scanner/url_parse.py` onto the core's IP canonicalisation
   (`_authority.coerce_ip`, `ip_key`).

## Gates, in order
- **C-11 first.** RECORD mode must leave the 456-row oracle byte-identical.
  Nothing else proceeds until this is green.
- **Differential parsing.** Every parser reading a string the system will act on
  is tested against the real consumer (`urllib`, the transport), never a fixed
  expectation list. W1 found 3,458 of 5,632 spellings disagreeing with
  `urllib.parse` before the fix. That class of bug must not return.
- **Outside the process.** Built wheel, clean venv, real LangChain: a poisoned
  tool result naming a destination leads to that tool call being blocked or
  flagged under ENFORCE, and the verdict unchanged under RECORD. A test that
  imports the module under test does not count.

## Test rules
- Failing test first, always. A fix without a test that fails without it does
  not count.
- Affected tests only while iterating. Never the full suite; CI runs it.
- Every milestone carries a sabotage proof: remove the fix, see named red,
  restore.
- Adversarial verification uses a different corpus than the build was tested on.

## STOP points
- After C-11, before any seam wiring.
- Before any change to the published wire format or verdict vocabulary.
- Any decision not settled above.

## Never
Merge, tag, release, publish, or force-push. Push the branch only.
