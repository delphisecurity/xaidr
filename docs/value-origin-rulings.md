# Value origin — rulings this build follows beyond the architecture

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

The specification is `docs/value-origin-architecture.md` in delphi-sentinel
(read at `origin/main` `01450c7`). This file records every place the core in
`xaidr/value_origin/` follows something **other than** that document's text:
the rulings of 2026-09-24 (batch 2), the six ambiguities those rulings left open
and how the owner settled each, the rulings of 2026-10-03 on what the build
found, and the decisions that still need a ruling. Where a ruling and the
document differ, the ruling wins.

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
UNRESOLVED. *Pinned by:* `R32-*`, `S20`. **Amended by R1 (2026-10-03):** the
parts that did parse are findings too.

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

## Rulings 2026-10-03

On what the A1 build found (below) and on the build's decisions. Settled by the
owner.

**R1: 3.2's mailbox-list evasion is fixed.** Under 3.2 as written,
`to="evil@x.example, junk"` was UNRESOLVED as a whole, even with
`evil@x.example` recorded untrusted, so it never blocked under ENFORCE. An
attacker appended junk and walked through. Now the value stays UNRESOLVED as a
whole (one `parse_failure` finding), **and** every part that parsed yields its
own finding, so an untrusted part decides the wire. A trusted or principal part
beside junk stays UNRESOLVED and does not newly block.
*Pinned by:*
- `R32-untrusted-plus-bad-part`, flipped from pinning the old behaviour (junk
  after, `,`).
- `R32-untrusted-junk-before`, `R32-untrusted-junk-semicolon` and
  `R32-two-untrusted-parts`.
- `R32-trusted-plus-junk` and `R32-one-bad-part`: neither blocks.
- `test_r1_an_untrusted_part_beside_junk_blocks_and_a_trusted_one_does_not`,
  which asserts `should_block` under ENFORCE for each of these.

**R2: percent-decoding hosts before UTS-46 is accepted as built** (formerly
build decision 1). It closes the same evasion shape as R1: without it,
`https://ev%69l.test/` walks past a recorded `evil.test` (`R36-percent-host`).

**R3: URL_PREFIX refusing `.` and `..` segments is accepted as built**
(formerly build decision 2). It is the no-trust direction (`S28b-dot-segment`).

**R4: V-19's two missed spellings are fixed.** Both were `no_destination`.
- **`http:evil.test`.** A WHATWG special scheme takes its authority after any
  run of `/` and `\`. The special schemes are `http`, `https`, `ws`, `wss` and
  `ftp`; `file` is never a destination (C-6). So `http:evil.test`,
  `http:/evil.test`, `http:\\evil.test` and `http:///evil.test` all name
  `evil.test`. The value is rewritten to `scheme://` and parsed as one. A
  non-special scheme without `//` has no host (`gopher:evil.test`); WHATWG and
  urllib.parse agree on that.
- **`169.254.169.254/latest`.** A scheme-less value that opens with a strict
  address literal is that address when a port, path, query or fragment
  follows. A strict literal is a dotted quad, or IPv6 in brackets.

*Pinned by:*
- `V19-special-no-slashes` and `V19-ip-path`.
- Their `-untrusted` twins, where the spelling would otherwise walk past a
  recorded untrusted address.
- `test_v19_every_spelling_resolves_to_the_host_urllib_parse_finds`. It
  compares the core with the host urllib.parse finds for 5,632 spellings:
  every scheme, separator, host form and tail. The 1.15.0 audit found nine of
  fifteen spellings of 169.254.169.254 getting past a rule that matched the
  scheme literal instead of the address; a rule of that shape fails this test.

**Build decisions 3 to 10 below are accepted as built.** That includes 6:
`file:` and `data:` are never destinations.

## Decisions made in the A1 build, ruled 2026-10-03

All ten are accepted.

1. **Accepted (R2).** **Percent-encoded URL hosts are decoded** before UTS-46,
   as WHATWG host parsing does. Otherwise `https://ev%69l.test/` would evade a
   recorded `evil.test` (`R36-percent-host`).
2. **Accepted (R3).** **URL_PREFIX refuses a value path with a `.` or `..`
   segment** (percent-decoded too). V-17 is silent. Without this,
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

## Decisions made in the R1 / R4 build that still need a ruling

Each is listed so it can be overruled, not so it can pass unnoticed.

1. **R1 treats a mailbox list whose quoting does not balance as junk.** The
   whole value fails, and its `,` and `;` are taken literally to find the parts
   that parse (`R32-untrusted-unbalanced-quote`). Without this,
   `evil@x.example, "` hides an untrusted mailbox exactly as `, junk` did, and
   `email.utils.getaddresses` reads `evil@x.example` out of it.
2. **R1's finding order.** The whole-value `parse_failure` finding comes first,
   then the parts that parsed, in text order.
3. **R4: what may follow the IP literal.** The ruled spelling is a dotted quad
   with a path. A port alone (`10.0.0.5:80`), a query and a fragment count too,
   and so does IPv6 in brackets. Each is the same address with a different
   locator.
4. **R4 takes strict literals only.** The integer spellings stay
   `no_destination` with no scheme; see the list below.
5. **R4's accepted costs.**
   - A CIDR like `10.0.0.0/8` now reads as `ip:10.0.0.0`. That is UNRESOLVED
     unless something recorded it.
   - A special-scheme value containing whitespace (`http:evil.test/a b`) is now
     `parse_failure`, which `http://evil.test/a b` already was.
   - `HTTP: 404` is not a URL, because a space follows the colon.
6. **R4 also reaches prose and results.** The prose URL scan already matched
   `http:///evil.test` but found it hostless and blanked it. Now it records
   `evil.test`. Prose `http:evil.test` was already recorded, by the bare-host
   scan.

## Found, reported, not fixed (the rulings as written produce these)

Every item except the last has a strict-xfail test. The test goes red, and so
has to be updated, the day its defect is fixed. The last item is a measurement
note.

- **Junk in the same part still hides an untrusted mailbox.** R1 works on the
  parts of a `,`/`;` split. `evil@x.example <` is one part, and it fails, so it
  is UNRESOLVED; `email.utils.getaddresses` reads `evil@x.example` out of it
  (`test_r1_residual_junk_inside_the_part_still_hides_an_untrusted_mailbox`).
- **V-19 integer IP forms with no scheme.** These all stay `no_destination`:
  `0xA9FEA9FE/latest`, `2852039166/latest`, `0251.0376.0251.0376/latest` and
  `169.254.43518/latest`. urllib.parse, given an implied `http://`, finds
  169.254.169.254 in each, and curl, which guesses `http://`, reaches it. V-19
  confines these spellings to a URL host because `2024/report` is a path
  (`test_v19_residual_integer_forms_with_no_scheme`).
- **A name with a port and no scheme.** `evil.test:8080/x` is `no_destination`,
  because V-19's `host/path` needs the path straight after the name
  (`test_v19_residual_a_name_with_a_port_and_no_scheme`).
- **Whitespace in a URL path hides its host.** Whitespace anywhere in a
  `scheme://` value is `parse_failure`, so `https://evil.test/a b` is
  UNRESOLVED even with `evil.test` recorded untrusted. WHATWG percent-encodes
  the space, and the host is still `evil.test`
  (`test_residual_whitespace_in_a_url_path_hides_its_host`).
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
