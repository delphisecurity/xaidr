# Value origin — rulings this build follows beyond the architecture

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

The specification is the value-origin architecture specification. This file
records every place the core in `xaidr/value_origin/` and its seams follow
something **other than** that document's text, as the behaviour they produce
today. Each rule names the tests that pin it. Where a ruling and the document
differ, the ruling wins. Every ruling here is settled; the decisions listed under
"Accepted as built" can still be overruled.

## 1. Ledgers: binding, lifetime and authority

**A ledger is explicit or implicit** (an internal attribute).

| entry point | binds |
|---|---|
| `begin_flow()`, `extract_context()` | a fresh EXPLICIT ledger, unconditionally (`bind_fresh_ledger`) |
| `xaidr.flow()` | what `begin_flow()` binds; on exit the ledger before the scope is put back |
| `record_principal_input()` (every input scan) | nothing bound: a fresh IMPLICIT ledger; implicit bound: replaced by a fresh implicit one, unless the input's principal text is the last one it recorded; explicit bound: kept |
| `bind_ledger()` | an explicit ledger iff nothing is bound; never rebinds |
| `record_hop()` | nothing |
| `clear_flow()` | unbinds |

`record_principal_input` binds *before* validating, so a faulting input still
ends the previous request's implicit authority. No public parameter controls
binding. *Pinned by:* supplementary `R31-*`, `test_ruling_3_1_changed_*`.

**The same input scanned again is the same request.** A host loop, or a
middleware such as LangChain's `before_model`, scans the user's message before
every model call. When an input's principal text is the one the implicit ledger
last recorded, the ledger is kept, with every tool result recorded in it, so a
destination a tool result named is untrusted at the next model turn. Another
input in between ends the request as before; an input with no principal text (an
inbound A2A message) always starts one. *Pinned by:*
`tests/test_value_origin_turns.py`.

**One input in several strings is one write.** An Agents SDK run's input list, a
CrewAI kickoff's input values, and the string variables of a Haystack
`user_prompt` are recorded together, each string its own span and each keeping its
own scan's verdict, so a later string never replaces an earlier one's record.
*Pinned by:* `test_a_multi_string_input_is_one_ledger_write`,
`test_a_crews_input_values_are_one_write_of_declared_spans`.

**Only text the principal wrote is principal input.** System, developer,
assistant and tool text, and text a framework renders from a template, never
authorizes a destination:

- an Agents SDK run's principal input is a plain string or a user message;
- a CrewAI kickoff's input values and, under `protect()`, a Haystack Agent's
  string template variables are the template variables the framework exposes:
  each is a DECLARED principal span, and the template text around them (the
  author's, and any retrieved document a non-string variable fills in) is scanned
  and not recorded. `delphi_hooks()` passed to an Agent without `protect()` does
  not see the run's variables and records the rendered message as before;
- LangChain's middleware records only the newest human message.

*Pinned by:* `test_system_and_developer_text_is_not_principal_input`,
`test_rendered_template_text_is_not_principal_and_string_variables_are`.

**History a request replays is recorded as what it is.** A tool output the model
reads again in a later request (a `ToolMessage` in a LangChain message list, a
`function_call_output` in an Agents SDK input list) is recorded in that request as
an untrusted tool output, once per ledger, so the destination a turn-1 tool result
named is untrusted at turn 2 as well. An output of a designated source is not
replayed: this request did not scan it, and an untrusted record would pin a read
the request makes of that source again (a read never raises). *Pinned by:*
`test_a_tool_results_destination_is_untrusted_at_the_next_user_turn` (LangChain
and Agents SDK).

**A destination the principal gave keeps authorizing for the rest of that flow,
never across requests.** Untrusted content never raises it, and nothing lowers it
(the write rule in `_ledger.py`). *Pinned by:* `S2`, `R31-*`, the reuse and
request-scope tests below.

**A ledger belongs to the request it is bound in, and closes when that request
ends.** A closed ledger reads as not bound everywhere, including in a context
copied from the request (a worker task, an executor job), so no later request
reads its authority. The requests are:

- each `concurrent.futures.ThreadPoolExecutor` work item: the first `Sensor`
  constructed with value origin on installs this once per process, and it
  touches only xaidr's own context variables;
- `xaidr.request_scope()`, for a server loop the sensor cannot see (`with` and
  `async with`);
- each CrewAI kickoff (`Crew.kickoff`, `akickoff`, `kickoff_async`) and each
  Agents SDK run (`Runner.run`, `run_sync`) hooked by `protect()`;
- each fresh `xaidr.flow()` scope;
- each `multiprocessing.pool.ThreadPool` task (an `apply`, or one chunk of a
  `map`), for pools created after the first such `Sensor`;
- each request through `xaidr.integrations.web.RequestScopeMiddleware` (WSGI;
  the request lasts until the server closes the response body) or
  `RequestScopeASGIMiddleware` (ASGI; lifespan messages pass through).

`request_scope()` always starts a new request. A hooked run joins a live hooked
run (an Agents SDK `Agent.as_tool`, a crew kicked off from a tool) or a live
`flow()`; inside a `request_scope()` or an executor job it is its own request. A
fresh `flow()` binds a ledger of its own and joins a live `request_scope()`,
hooked run or `flow()`; inside an executor job it is its own request. So one job
serving several users keeps each run and each `request_scope()` to itself, and a
request left open never takes a later request's input. A
ledger bound outside the request being opened (a `begin_flow()` with no request
around it, a pool initializer's, an enclosing request's) is hidden inside it,
and back when it ends. An exit ends every request opened inside it, and a
`request_scope()` exited in another context (a generator closed on another
thread) still ends its request, unless that one instance has several requests
open at once (shared across threads), when the exit cannot tell which is its own. In a request the host or a framework declares
(`request_scope()`, a hooked run) every input keeps authorizing for the rest of
it; in an executor job, which may be a loop serving one user after another, a new
input still ends the previous implicit ledger (S-2). A run hooked inside another
hooked run (an Agents SDK `Agent.as_tool`, a crew kicked off from a tool) scans
its input and does not record it as principal input: that input is the outer
run's model text. In an Agents SDK run's input list, only a string or a user
message is principal input; a replayed tool output is recorded as an untrusted
tool output, and system, developer and assistant text is scanned and not recorded. A
`flow()` scope joins only a scope that is still open, inside a request that is
still live. A `clear_flow()` inside a `flow()` closes the scope, and the scope's
request stays open, joined by nothing, until the scope's own exit, so a ledger
bound in between closes then.

**Where the host's own code decides how long a request lasts:**

- A `flow()` entered by hand (`__enter__()`) and never exited keeps its flow's
  chain, tiers and correlation id in that context; its value-origin ledger closes
  with the request it ran in. A `flow()` opened later in that context finds the
  flow active and, as above, leaves its chain alone, so provenance there can name
  the earlier request's principal. The first time a scope finds such an entry it
  logs one warning per process. `with xaidr.flow(...):` always exits.
- A hooked framework run whose coroutine is started and never finished (driven by
  hand, without a task, and abandoned) keeps its request open in the context that
  started it, until that context's enclosing request ends.
- Executor jobs, ThreadPool tasks, hooked runs, `flow()` and the middleware above
  are the requests the sensor sees begin; any other server loop marks each request
  with `request_scope()`. A `flow()` scope opened
while a flow is already active (a `begin_flow()`, an `extract_context()`, a
recorded hop) leaves that flow's chain, tiers, correlation id and inbound mark
exactly as they are, on entry and on exit, so it never loosens the privilege-tier
gate; it gets its own ledger (Q-G (b), 2026-10-21;
`test_a_scope_over_an_active_flow_leaves_its_chain_and_tiers_alone`). Every other
request puts back, at its exit, the chain, correlation id, tiers and inbound mark
set inside it, so a request whose headers are stripped never inherits the
previous request's tier on a reused thread; entry changes none of them, so a
request opened inside a delegated one still sees the delegation.
*Pinned by:* `tests/test_value_origin_reuse.py`, `tests/test_value_origin_servers.py`,
`tests/test_value_origin_request_scope.py`.

**An inbound A2A message starts a fresh ledger** through the input path (an
implicit ledger is replaced, an explicit one is kept), and records no
destination (Q21).

**A flagged input records nothing as principal**: neither destinations nor key
n-grams (3.5). Every candidate in it is recorded untrusted. *Probe:*
`R35-flagged-ngrams`.

## 2. How a value is read

**The reading principle (2026-10-21).** If any real client could send to an
address, the core reads the value as going there. A value whose spellings have
more than one reading names every one of them. This applies to every rule below.

### URLs

- **Every reading of the authority split is a destination** (Q1). The readings:
  WHATWG (a backslash is a slash; urllib3 and ada agree); RFC 3986 as CPython
  3.12.2's `urlsplit(...).hostname` reads it (httpx and urllib.parse agree),
  written out so it is the same on every interpreter; and, where `urlsplit`
  refuses the WHATWG string, that string's authority split anyway. Each distinct
  authority is its own finding. *Pinned by:* `Q1-*`,
  `test_q1_every_reading_of_the_authority_split_is_a_finding`, and
  `tests/test_differential_oracles.py` (spellings × urllib.parse, httpx, urllib3,
  ada-url; it refuses to run unless every oracle is installed).
- **A special scheme takes its authority after any run of `/` and `\`** (R4):
  `http:evil.test`, `http:/evil.test`, `http:\\evil.test` and
  `http:///evil.test` all name `evil.test`. The special schemes are `http`,
  `https`, `ws`, `wss` and `ftp`. A non-special scheme without `//` has no host.
  `file:` and `data:` are never destinations; `mailto:<addr>` is a mailbox.
- **Tabs and newlines are removed from a URL**, as WHATWG and `urlsplit` remove
  them. Other whitespace counts where it lands: in a host it is no host for that
  reading; in a path, query or fragment it is percent-encoded by WHATWG, and the
  host stays readable (`https://evil.test/a b` names `evil.test`). *Pinned by:*
  `test_whitespace_in_a_url_path_leaves_its_host_readable`.
- **Percent-encoded hosts are decoded before UTS-46**, as WHATWG host parsing
  does (`https://ev%69l.test/` names `evil.test`; `R36-percent-host`).
- **UTS-46: nontransitional, Unicode 13.0** (S-4). ß stays ß (`xn--zca`), as
  browsers resolve it. CheckBidi on; STD3 rules off; CheckHyphens and
  VerifyDnsLength off. ZWJ/ZWNJ labels fail (CONTEXTJ needs Joining_Type data
  the stdlib lacks). The mapping table, bidi classes and combining marks are
  vendored from Unicode 13.0 (`_idna_data.py`), Python 3.10's `unicodedata`
  version. A URL host that fails UTS-46 yields `dns:<raw host lowercased>`,
  which matches only itself. Unicode domain labels are accepted and compared as
  A-labels (3.6); `R36-homoglyph-*`.
- **A URL is tried before the mailbox rule** (S-3): a value that opens with
  `scheme://`, or is a scheme-less `host/path`, is a URL even when it carries
  `@` (`R32-url-first`).
- **A `scheme://` value that `urlsplit` refuses** (an unterminated IPv6 bracket)
  is `parse_failure` as a whole, and every host the other readings find is a
  finding beside it (R1's shape; `Q1-urlsplit-refusal`).

### Scheme-less values

A client that guesses `http://` (curl) sends each of these where the core reads
it:

- **`host[:port]/path`**: a name of at least two labels with an alphabetic last
  label, an optional port, then a path (`evil.test/x`, `evil.test:8080/x`). It is
  read as `http://` + the value, every reading included.
- **An address literal followed by a port, path, query or fragment**: a dotted
  quad or IPv6 in brackets, in a result or an argument
  (`169.254.169.254/latest`, `10.0.0.5:80`).
- **An address in any inet_aton spelling followed by a port, path, query or
  fragment**, in an argument: hex, octal, decimal and short dotted forms
  (`0xA9FEA9FE/latest`, `2852039166/latest`, `0251.0376.0251.0376/latest`,
  `169.254.43518/latest` all read 169.254.169.254; `2024/report` reads
  0.0.7.232). Results record only the strict forms above, so a path in a file
  listing is not recorded as an address. *Pinned by:*
  `test_integer_ip_forms_with_no_scheme_read_as_the_address_they_reach`,
  `test_an_integer_host_with_a_path_reads_as_its_address`.
- **Not destinations:** a bare hostname (V-19), with or without a port; a bare
  number or version (`2852039166`, `1.2`); a dotted value no resolver reads as an
  address (`999.1.1.1/x`); a name whose last label is not alphabetic
  (`report.v2/summary`); a scheme-less value with whitespace in it.
  *Pinned by:* `test_values_that_are_not_destinations`.

### Addresses

- **A name is keyed by its registrable domain**: the PSL algorithm over both
  sections with the default `*` rule; a host that is itself a public suffix, or
  one label, is kept whole. So `docs.northbank.example` and a principal's
  `northbank.example` are the same destination (`pos-drift-*`).
- **One normaliser**: every literal form (hex, octal, decimal, short dotted,
  IPv4-mapped IPv6), mapped addresses unwrapped before rendering
  (`coerce_ip`, `ip_key`).
- **An empty hex part is 0**: `https://0x.0x.0/` is `ip:0.0.0.0`, as WHATWG's IPv4
  number parser reads it on every platform. The macOS resolver (`inet_aton` and
  `getaddrinfo` with `AI_NUMERICHOST`, measured on macOS 26.6) reads an empty hex
  part only where a later part follows it: it reads `0x.0x.0`, `0x.1.1.1` and
  `0x.0`, and refuses `0x`, `0x.0x`, `127.0x`, `127.1.0x` and `0x.0x.0x.0x`. What it
  refuses, Python's clients send as a DNS name, so for those shapes the `ip:` key
  is WHATWG's reading alone. `M3-empty-hex-part`;
  `test_an_empty_hex_part_is_the_zero_address`;
  `test_the_empty_hex_ruling_states_what_the_macos_resolver_reads`.
- **Integer parts are digit-checked**, not left to `int()`, which takes `_`
  separators no resolver reads (`0x_1.1.1.1` is a name).
- **The macOS resolver's readings are read on every platform** (Q22, re-ruled):
  a leading-zero dotted quad read as decimal, the IPv4 tail of an IPv6 literal
  read the same way, and one number above 2**32 - 1 wrapped modulo 2**32
  (`4294967296` and `0x100000000` read `0.0.0.0`; `0x1A9FEA9FE` reads
  169.254.169.254). Each is one more finding beside the inet_aton reading, public
  addresses included. *Pinned by:* `Q22-rerule-macos-decimal-quad`,
  `tests/test_differential_oracles.py` (the `_macos_reading` rows and
  `test_q22_*`).

### Mailboxes

- **A value with `@` that is not a URL is a mailbox-list candidate** (3.2). It is
  split on `,` and `;` outside `<…>` and `"…"`. Without `@` it goes to the other
  schemes or `no_destination`. An empty part (`"a@x.example; "`) is skipped.
- **An `@` that is not an address does not make an address list** (L5 F3). When
  no part is an address, or shaped like one (one token with text on both sides of
  the `@`, or a display name and an angle address), the value is read like any
  other: `ping me @ 5pm` names nothing, and in `curl -d @file https://host` the
  argument walk observes the host. One address the grammar refuses
  (`jürgen@x.example`) is still an unparseable address list (3.6).
  *Pinned by:* `test_an_at_sign_that_is_not_an_address_is_not_an_address_list`,
  `test_a_call_whose_text_has_an_at_sign_stays_authorized`.
- **One failing part makes the whole value `unresolved`, and every part that
  parsed is its own finding** (R1), so an untrusted part decides the wire. A
  trusted or principal part beside junk stays `unresolved` as a whole.
  *Pinned by:* `R32-*`, `S20`,
  `test_r1_an_untrusted_part_beside_junk_blocks_and_a_trusted_one_does_not`.
- **A mailbox inside a part that does not parse is a finding too**, when the part
  holds one address and only junk (no letter or digit) or a display name opening
  `<` surrounds it: the address in `evil@x.example <` or `Bob <evil@x.example` is
  read, as `email.utils` reads it. Prose that mentions an address
  (`Please send the report to bob@corp.example.`) is not a recipient list, and a
  candidate that starts mid-word (`jürgen@…` is not `rgen@…`) or runs into more
  text (`user@evil.test/x`) is not a mailbox. *Pinned by:*
  `test_an_untrusted_mailbox_beside_junk_in_the_same_part_decides_the_wire`,
  `test_prose_that_mentions_an_address_is_not_a_recipient_list`, and the mailbox
  checks in both differentials: each mailbox finding is one written verbatim in
  the value, or one at a domain `email.utils` reads.
- **Quoting that does not balance is junk**: the whole value fails, and its `,` and
  `;` are taken literally to find the parts that parse
  (`R32-untrusted-unbalanced-quote`).
- **The local part is ASCII by grammar, and lowercased.** A non-ASCII local part
  is `unresolved` (3.6; `R36-nonascii-local`). The domain may be Unicode and is
  UTS-46-encoded. Lowercasing is the one fold applied to a local part
  (`V23-local-part-lower`, `pos-format-*`); no plus-stripping and no dot removal,
  because those collide distinct mailboxes (S18).

### Phones and bare hosts in prose

- **`tel:` is for `+`-prefixed phones only.** A national number needs a region to
  normalise.
- **The span recorder accepts a bare hostname in prose** if its last label is an
  ICANN TLD in the vendored suffix list, or an RFC 2606/6761 name (`example`,
  `test`, `invalid`, `localhost`) (3.4). The same filter applies to result text
  (S-5): one candidate extractor serves spans and results. A filename that ends in
  a real TLD (`notes.md`) records `dns:notes.md`; that matters only if an action
  goes to that host (`R34-icann-tld-cost`).

## 3. A value that names more than one destination

The core never picks one. Every destination a value names is its own finding,
and the weakest decides the wire (R1, Q1). `authority_of` returns `None` for a
value with two authorities, exactly as for a two-mailbox list, and
`extract_destinations` reports all of them.
*Pinned by:* `test_q1_authority_of_answers_none_for_a_value_with_two_authorities`.

## 4. Trust

- A `URL_PREFIX` designation matches with no userinfo, equal lowercased schemes,
  equal lowercased hosts, equal ports after mapping 80/443 to absent, and the
  pattern's path segments a segment-wise prefix of the value's. Query and fragment
  are ignored.
- **A value path with a `.` or `..` segment never matches** (percent-decoded
  too): `/public/../private/x` is not trusted as `/public` (R3,
  `S28b-dot-segment`).
- **A value with more than one reading never matches**: across the 47,124
  spellings of the differential corpus, every value a designation matches is one
  the core reads as exactly one authority
  (`test_a_url_prefix_designation_never_trusts_a_value_with_several_readings`).
- A trusted read with several authorizing designations takes both the label and
  the declared flag from the first authorizing designation (in the operator's
  order). `DestinationFinding.span_declared` is set for `TRUSTED_SOURCE` as well
  as `PRINCIPAL`; `TRUSTED_SOURCE` with `span_declared=False` maps to wire
  `principal_undeclared_span`.

## 5. Recording and its bounds

- **`record_principal_input` writes two all-or-none units** (S-6): its
  destinations, then its key n-grams, so a long prompt's n-grams can be dropped
  without dropping the principal's addresses. `record_tool_result` is one unit,
  and atoms found past a bound are a separate unit after it.
- **Budgets.** 10,000 destination digests and 65,536 key n-grams per ledger, each
  its own budget. Key n-grams come from the first 64 KiB of principal input;
  destination atoms come from all of it. The atom pass past a bound is bounded by
  WORK: each scanned character costs 1 and each candidate examined costs 64,
  500,000 units per seam call (`ATOM_WORK_BUDGET`); a result's examined pass is
  bounded the same way at 1,000,000 units (`EXAMINED_WORK_BUDGET`).
- **Observed atoms** (L5 F4, record only): an argument value the walk examines
  whole that is not wholly one destination is scanned for destination atoms
  (prose, a command line, a mailbox part that does not parse). Each atom is on
  `CallVerdict.observed` with its ledger origin, and never decides the wire, the
  verdict or an action. Past a bound a value short enough to read whole is read
  whole, and its atoms decide as before, so the same value names the same
  destinations wherever it sits. A mailbox atom that starts mid-word in a script
  that spaces its words (`jürgen@x.example`) is not read as the address after the
  letter. *Pinned by:* `tests/test_value_origin_padding.py`.
- **The argument walk**: depth-first in insertion order, a dict's keys walked as
  leaves before its values, sets in sorted order (hash randomisation would
  otherwise change which leaves the 64-leaf bound selects). A walk that hits a
  bound yields one `walk_bound` finding, whose `path` is `()`.

## 6. Wire values and what blocks

Fifteen wire values. `verdict_of` is total over them, and a string outside them
is `NOT_EVALUATED`, matching `row_text`'s unrecognised row.

| wire | verdict | blocks under ENFORCE |
|---|---|---|
| `principal`, `principal_undeclared_span`, `trusted_source` | authorized | no |
| `untrusted_source` | unauthorized | **yes** (`ORIGIN_UNTRUSTED_DESTINATION`, category `untrusted_destination`) |
| `unresolved`, `argument_bound` | unresolved | no |
| `result_unread` | not evaluated | **yes** (`ORIGIN_UNEXAMINABLE_SOURCE` with `intent.value_origin_untrusted`, category `unexaminable_source`) |
| `write_dropped` | not evaluated | **yes** (as `result_unread`) |
| `no_destination`, `no_flow`, `ledger_absent`, `ledger_saturated`, `input_truncated`, `result_truncated`, `extraction_incomplete` | not evaluated | no |

- **`result_unread`**: a tool result from httpx, requests, urllib3 or aiohttp is
  passed on unread, so as not to consume a stream; a destination that then traces
  to nothing reads `result_unread` (Q18).
- **`write_dropped`**: a destination write the ledger did not accept. That is a
  full ledger, or a write lost to a fault: a raising `model_dump` in the examined
  pass, a span list that does not concatenate to the text, a span item that is
  not a `Span`, a non-string input (ruling 5). Past the examined bound, a raising
  node is confined to its node and reads `result_unread`. *Pinned by:*
  `tests/test_value_origin_drop.py`.
- **The order** when the weakest finding is not `untrusted_source`: a state that
  blocks outranks every state that does not (`result_unread`, then
  `write_dropped`), then `extraction_incomplete`, `argument_bound`,
  `ledger_saturated`, `result_truncated`, `input_truncated`. An untrusted finding
  outranks all of them.
- `ORIGIN_UNTRUSTED_DESTINATION_KEYED` (the keyed variant) is reserved; nothing
  emits it.

## 7. The wire field

`valueOrigin` is on every tool-call event, behind `value_origin_wire`. The
default `"v1"` emits exactly the nine values the consumer accepts and withholds
the other six, naming each in a warning once; `"v2"` emits all fifteen; `"off"`
emits nothing. `SCHEMA_VERSION` is 0.3.0 (Q14). The Splunk TA's metadata names
schema 0.2.0, and `KV_MODE = json` extracts `gen_ai.security.value_origin` from
0.3.0 events.

## 8. The paid product

The paid product is the open sensor plus an overlay, and inherits open's
behaviour for everything in this file, including S25 (a principal-only emit with
`set_origin` reads `no_flow` then `unresolved`) and every SEMANTIC row in the
conformance files.

## 9. Accepted as built

Each is current behaviour and can still be overruled.

1. A mailbox list whose quoting does not balance is junk (§2, Mailboxes).
2. R1's finding order: the whole-value `parse_failure` finding first, then the
   parts that parsed, in text order.
3. In a saturated ledger a part that parsed is a destination like any other, so
   `x@…, junk` whose part does not trace reads `ledger_saturated`; an untrusted
   part still outranks it
   (`test_r1_a_parsed_part_that_misses_in_a_saturated_ledger_reports_saturation`).
4. After an address literal, a port alone (`10.0.0.5:80`), a query, a fragment or
   a path counts, and so does IPv6 in brackets.
5. Results record scheme-less addresses only in the strict literal forms; the
   inet_aton forms are read in arguments (§2, Scheme-less values).
6. A CIDR like `10.0.0.0/8` reads `ip:10.0.0.0`, which is `unresolved` unless
   something recorded it. `HTTP: 404` is not a URL (a space follows the colon).
7. The prose URL scan records `http:///evil.test` as `evil.test`; prose
   `http:evil.test` is recorded by the bare-host scan.
8. The RFC 3986 reading is a written-out split that reads exactly what CPython
   3.12.2's `urlsplit(...).hostname` reads, the most lenient version measured,
   so it is the same on every interpreter. Where `urlsplit` refuses the WHATWG
   string, WHATWG's own bracket rule applies: a `[` must open the host and
   enclose an IPv6 literal.
9. Where `urlsplit` refuses the WHATWG string, the value is `parse_failure` and
   every host the split finds is a finding beside it.
10. `authority_of` returns `None` for a value with two authorities (§3).
11. One over-read class is named in the differential:
    `urlsplit-bracket-validation`, hosts CPython 3.12.2's urllib.parse reads and
    later patch releases refuse. It is checked both ways: it absorbs nothing on an
    interpreter that reads like 3.12.2 and must be needed on one that does not.
    The mailbox reading is named the same way, and each of its findings is checked
    against `email.utils`.
12. Integer parts are digit-checked (§2, Addresses).
13. A name with a port and nothing after it is a bare host, and not a destination.
14. Request kinds (`_JOINS`): `request_scope()` joins no live request, a hooked
    run joins only a hooked run or a `flow()`, a `flow()` joins any request the
    host or a framework declared, and an executor job joins any. So a hooked run,
    or a `request_scope()`, inside a `request_scope()` does not see input the host
    recorded earlier in the enclosing scope, and a `begin_flow()` with no request
    around it is not visible inside a hooked run; the run records its own input.
15. An executor job keeps S-2: a new input ends the previous implicit ledger.
16. In an Agents SDK run's input list, strings and user, system and developer
    messages are principal input.
17. The first-write lock: the S22 first-write test and the all-or-none
    visibility test both stay in the suite; the second is the reliable detector of
    a ledger without its lock.
