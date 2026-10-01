# Value origin — rulings this build follows beyond the architecture

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

The specification is `docs/value-origin-architecture.md` in delphi-sentinel
(read at `origin/main` `01450c7`). This file records every place the core in
`xaidr/value_origin/` follows something **other than** that document's text:
the rulings of 2026-09-24 (batch 2), the six ambiguities those rulings left open
and how the owner settled each, and the decisions made during the build that
still need a ruling. Where a ruling and the document differ, the ruling wins.

## Rulings 2026-09-24, batch 2

**3.1 Ledger binding.** A ledger is *explicit* or *implicit* (an internal
attribute). `begin_flow` and `extract_context` bind explicit
(`bind_fresh_ledger`). `record_hop` binds explicit only when nothing is bound,
otherwise it is a no-op (`bind_ledger`). An input scan with nothing bound binds
implicit. A later input scan replaces an implicit ledger (the V-27 cross-user
fix), never an explicit one. Public `bind_ledger()` is the explicit bind and
never rebinds an explicit ledger. No new public parameter.
*Pinned by:* supplementary `R31-*`.

**3.2 Mailbox candidates.** A value is a mailbox-list candidate only if it
contains `@`. Without `@` it goes to the other schemes or `no_destination`. With
`@`, it is split on `,` and `;`, and one failing part makes the whole value
UNRESOLVED. *Pinned by:* `R32-*`, `S20`.

**3.3 Unresolved findings.** `Finding.destination` is `Authority | None`, and it
is `None` iff extraction left it unresolved, with reason `walk_bound` or
`parse_failure`. `expected.jsonl` lists these with a reason and no destination.
`extract_destinations` returns `tuple[tuple[Finding, ...], bool]`: that fixes
invalid Python and is a correction, not a design change.
*Pinned by:* `test_interface`, `S16`, `R32-one-bad-part`, `R33-unparseable-url`.

**3.4 Bare hosts in principal prose.** The span recorder accepts a bare hostname
if its last label is an ICANN TLD in the vendored suffix list, or an RFC
2606/6761 reserved name (`example`, `test`, `invalid`, `localhost`). Argument
extraction keeps rejecting bare hosts (V-19). **Accepted cost:** a filename like
`notes.md` collides with a real TLD, so naming it records `dns:notes.md`. That
matters only if an action goes to that host (`R34-icann-tld-cost`).

**3.5 Flagged input records nothing as principal.** Neither destinations (V-9)
nor lookup-key n-grams (C-3). *Probe:* `R35-flagged-ngrams`, which goes red if a
flagged input's n-grams are recorded.

**3.6 IDNA wins.** Unicode domain labels are accepted and UTS-46-encoded to
A-labels before comparing. Non-ASCII local parts are UNRESOLVED. Reason:
rejecting non-ASCII domains yields `unresolved`, which never blocks, so it would
be an evasion. *Homoglyph cases:* `R36-homoglyph-read`,
`R36-homoglyph-not-principal`.

**3.7 Two PRs.** A1 is the core package: pure, no seams. A2 is the seam wiring
and starts only after A1 merges. This file ships with A1.

## Ambiguities the rulings left open — settled by the owner, 2026-09-24

Each was reported before any code depended on it. Every settlement below is the
owner's choice, not the builder's.

| # | question | settled |
|---|---|---|
| S-1 | 3.3's `Finding` against §1.2's `DestinationFinding` | **Two types.** `Finding{path, destination: Authority \| None, reason: UnresolvedReason \| None}` is what `extract_destinations` returns. `DestinationFinding` keeps its fields, except `authority` is renamed `destination: Authority \| None` and it gains `reason`. `UnresolvedReason` is a str enum `{walk_bound, parse_failure}`. All three are exported. |
| S-2 | which public entry point binds the implicit ledger (3.1, no new parameter) | **`record_principal_input` binds.** Nothing bound → a fresh implicit ledger. Implicit bound → replaced by a fresh implicit ledger. Explicit bound → kept. It binds *before* validating, so a faulting input still ends the previous request's authority. This drops §1.4's "Does not bind" for that one function. `bind_ledger()` stays a no-op whenever anything is bound, which is what `record_hop` needs. |
| S-3 | 3.2 against URLs that carry `@` (`https://corp.example@evil.test/`) | **URL first.** A whole value that opens with `scheme://`, or is V-19's `host/path`, is tried as a URL before the mailbox rule, so C-6/V-23 hold and the host is `evil.test`. The literal reading made the userinfo spelling UNRESOLVED, an evasion of a recorded untrusted host (`R32-url-first`). |
| S-4 | 3.6's "UTS-46" against the doc's stdlib `idna` codec (IDNA2003) | **Nontransitional, Unicode 13.0.** ß stays ß (`xn--zca`), as browsers resolve it. CheckBidi on; STD3 rules off; CheckHyphens and VerifyDnsLength off. ZWJ/ZWNJ labels fail, because CONTEXTJ needs Joining_Type data the stdlib lacks. The mapping table, bidi classes and combining marks are vendored from Unicode 13.0 (`_idna_data.py`). 13.0 is Python 3.10's `unicodedata` version, so every valid code point is assigned on every supported interpreter, and NFC is stable for assigned code points. On failure, an argument URL host yields `dns:<raw host lowercased>` (V-23) and a mailbox is UNRESOLVED. |
| S-5 | whether 3.4's TLD filter applies to bare hosts in **result** text | **The same filter for both.** One candidate extractor serves spans and results (`R34-result-same-filter*`). Cost: a poisoned read that names a bare `evil.corpnet` (no scheme, non-ICANN last label) is not recorded, so a call there is `unresolved`. Scheme URLs are unaffected. |
| S-6 | V-16(b) "each call all-or-none" against V-16(d) "destinations before n-grams" | **Two atomic units.** `record_principal_input` writes its destinations as one all-or-none unit, then its n-grams as a second, so a long prompt's n-grams can be dropped without dropping the principal's addresses (`test_v16d_*`). `record_tool_result` is one unit. |

## Decisions made in the build that still need a ruling

Each one is either the safe direction or a WHATWG-consistent reading of an
existing rule. Each is listed so it can be overruled, not so it can pass
unnoticed.

1. **Percent-encoded URL hosts are decoded** before UTS-46, as WHATWG host
   parsing does. Otherwise `https://ev%69l.test/` would evade a recorded
   `evil.test` (`R36-percent-host`).
2. **URL_PREFIX refuses a value path with a `.` or `..` segment**
   (percent-decoded too). V-17 is silent. Without this,
   `/public/../private/x` is trusted as `/public`. Refusing is the no-trust
   direction (`S28b-dot-segment`).
3. **`verdict_of` of a string outside the nine returns `NOT_EVALUATED`**
   instead of raising, keeping §1.4's never-raises contract. This matches
   `row_text`'s not_recorded row for an unrecognised value.
4. **An empty part of a mailbox list is skipped** (`"a@x.example; "`), not
   treated as a failing part.
5. **Sets in arguments are walked in sorted order.** Their iteration order
   changes with hash randomisation, and the 64-leaf bound would otherwise select
   different leaves in different processes.
6. **`file:` and `data:` URLs are never destinations**, even `file://host/…`
   (C-6: file-system writes belong to L2). `mailto:<addr>` is a mailbox.
7. **A `scheme://` value that `urlsplit` rejects** (for example an unterminated
   IPv6 bracket) is `parse_failure`, not `no_destination`.
8. A `walk_bound` finding's `path` is `()`.
9. A trusted read with several authorizing designations takes **both the label
   and the declared flag** from the first authorizing designation (V-8(f) names
   the label only).
10. `DestinationFinding.span_declared` is set for `TRUSTED_SOURCE` as well as
    `PRINCIPAL` (C-3a, C-20). `TRUSTED_SOURCE` with `span_declared=False` maps to
    wire `principal_undeclared_span`.

## Found, reported, not fixed (the rulings as written produce these)

- **3.2 lets a junk part hide an untrusted mailbox.** Under 3.2,
  `to="evil@x.example, junk"` is UNRESOLVED as a whole, even when `evil@x.example`
  is recorded untrusted. So it never blocks under ENFORCE
  (`R32-untrusted-plus-bad-part` pins the current behaviour). A possible fix,
  recorded but not chosen: the whole value is UNRESOLVED, *plus* a finding for
  each part that did parse.
- **V-19 leaves two argument spellings as `no_destination`.** `http:evil.test`
  (no `//`, which WHATWG accepts for special schemes) and `169.254.169.254/latest`
  (a bare dotted quad with a path; `url_parse` catches it, V-19 does not).
- **The first-emission race is rarely observable through the public API.** The
  unlocked window in this core is one `_merge` call, inside a much longer
  extraction. With the lock removed, the S22 first-emission test went red in 1 of
  3 measured runs. The lock's other guarantee, all-or-none visibility of a
  multi-entry write, went red in 20 of 20 runs on 3.12 and on 3.14. That second
  test is the reliable R4 detector. Both tests stay in the suite.

## What A1 does not do

It adds no seams, sends nothing anywhere, and changes neither paid nor the Brain.
`scanner/url_parse.py` is unchanged. The IP canonicalisation it will import from
the core is `_authority.coerce_ip` / `ip_key`, and moving `url_parse` onto it is
A2. The 456-row oracle is untouched by A1 because nothing calls the core yet.
Showing that RECORD mode leaves it byte-identical is A2's obligation (C-11).
