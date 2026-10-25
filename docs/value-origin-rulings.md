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
- each run of an agent LangChain's `create_agent` built under `protect()`
  (LangGraph's `Pregel.stream` and `astream`, which `invoke` and `ainvoke` run
  through): its ledger is bound when the run starts, outside every node, so the
  model turns, the tools node and the replayed history share it with no
  `xaidr.flow()` around the run, sync and async alike, on every interpreter.
  *Pinned by:* `tests/test_value_origin_real_runs.py`;
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
  with `request_scope()`. The OUTERMOST `flow()`
scope starts fresh (Q-G, decided 2026-10-23; this replaces Q-G (b) of
2026-10-21, under which a scope opened over any active flow kept its chain and
correlation id): a ledger, a correlation id or a chain the context already holds
(a `begin_flow()` never cleared that recorded no hop after its principal entry, a
scope a request left open, a leftover implicit ledger) is set aside for the scope
and put back at its exit, and one warning per occurrence names what was set aside
by kind and count, never by value. Delegation evidence is kept: when the context
holds the inbound mark or a hop that is not the principal's own entry (an
`extract_context()`, a recorded upstream hop), the chain, tiers and inbound mark
stay as they are on entry, so the scope never loosens the privilege-tier gate,
its `principal=` is not applied, and only the ledger is the scope's own. The
correlation id is kept with them when the context holds a flow; over the inbound
mark and no flow, the scope mints one of its own. At exit the scope puts back
everything as it was at entry, the delegation included, so a tier an
`extract_context()` read inside the scope ends with it. A `flow()` cannot tell a
leftover agent hop from the current request's, so a leftover chain that carries
one is kept too. (Accepted by the owner, 2026-10-23.) The hop a sensor records
for its own scan is such a hop: a `begin_flow()` never cleared that a scan ran
inside is kept, chain and correlation id with it, and the warning says the chain
was kept. `extract_context()` reads the chain, tiers and correlation id from the
headers alone, replacing what the context held, so stripped headers read tier 4
before the scope, inside it, and after an earlier request on the same thread.
Call `extract_context()` inside the scope or before it; either keeps the
delegation. *Pinned by:* `tests/test_value_origin_flow_fresh.py`,
`test_a_scope_over_an_active_flow_leaves_its_chain_and_tiers_alone`,
`test_flow_scope[tier_gate]`. *(Corrected 2026-10-23: this paragraph said that
over delegation evidence the chain, tiers, correlation id and inbound mark "stay
exactly as they are", and named every `begin_flow()` never cleared as set aside.
A correlation id is minted over the inbound mark alone, a scan inside a leftover
`begin_flow()` makes it delegation evidence, and (fixed in this build) a
delegated scope's exit put back only its ledger. It also listed
`check_tier_gate`, a helper, as a test.)*
Every other
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
  written out so it is the same on every interpreter; and, where that split
  refuses the WHATWG string, that string's authority split anyway. A backslash is
  part of the RFC 3986 host: httpx, urllib.parse and urllib.request hand
  `docs.example\x.evil.test` to the resolver whole, so it is read whole
  (`dns:evil.test`), beside WHATWG's `docs.example`. Each distinct authority is
  its own finding. *Pinned by:* `Q1-*`,
  `test_q1_every_reading_of_the_authority_split_is_a_finding`, and
  `tests/test_differential_oracles.py` (spellings × urllib.parse, httpx, urllib3,
  ada-url; it refuses to run unless every oracle is installed).
- **A name a client resolves is read as a destination** (decided by the owner,
  2026-10-23). urllib.request and http.client hand the resolver the host as they
  split it, and each such host is read, beside every other reading:
  urllib.request unwraps `<URL:…>`, `<…>` and `URL:…`, percent-decodes the netloc
  and keeps its userinfo in the host (`http://ops@sink.example/` resolves
  `ops@sink.example`); http.client takes a port after the last `:` that follows any
  `]`, so an unbracketed IPv6 address loses its last group to the port and a host
  can keep a colon (`https://sink.example:8443:` resolves `sink.example:8443`) or a
  bracket, which no numeric parser reads; and a numeric host with a trailing dot
  (`10.9.8.7.`) is a DNS name to the resolver and to every Python client.
  http.client's port is whatever `int()` takes, and `int()` takes the decimal
  digits of every script its interpreter's Unicode knows, so a port written in
  any script's digits (Unicode 16.0's, the newest a supported interpreter
  carries) splits the host as a port in ASCII digits does. urllib.request's
  default opener resolves more than http and https (measured on every
  interpreter, `tests/test_value_origin_client_gate.py`): its FTP handler
  resolves the host after the last `@`, percent-decoded a second time, and its
  file handler looks a non-local `file:` host up (`Request.host` less its port up
  to 3.13, the netloc as written from 3.14). requests, on macOS, looks up
  `urlparse(url).hostname` of a URL of any scheme to decide whether the system
  proxy settings exempt it, before it refuses a scheme it does not send. Each of
  those names is read. No
  public DNS zone holds a label with `@`, `:` or `[`, or a numeric top label, but a
  hosts file, a search domain or a private resolver can answer one, so each is
  read as the key the resolver reaches. A non-ASCII host is read as the socket
  layer encodes it, IDNA 2003 (`straße` is `strasse`), as every supported
  interpreter encodes it (`_idna.idna2003`), the same list on every interpreter.
  The codec depends on the interpreter twice. Its `stringprep` table B.3: a fixed
  interpreter (3.10.22, 3.11.17, 3.12.15, 3.14.8, 3.14.9) encodes by RFC 3454's
  table B.3; an unfixed one (3.10.20, 3.10.21, 3.11.15, 3.12.2, 3.12.13, 3.12.14,
  3.14.5, 3.14.7, measured 2026-10-25) lowercases a code point B.3 does not map by
  its own Unicode, so 3.12.2 lowercases `Ⴜ` and 3.12.15 keeps it. And its NFKC,
  which takes decompositions from Unicode 3.2 but combining classes and
  compositions from the interpreter's own Unicode, so a pair of code points
  Unicode 3.2 left unassigned composes on 3.14 and not on 3.10. The core writes
  out each of those encodings from vendored data (RFC 3454's tables, and Unicode
  16.0 by age, in `tests/published_vectors/`). *Corrected 2026-10-25:* until then
  this paragraph said the encoding was written out from RFC 3454's tables and
  Unicode 3.2, "so the name is the same on every interpreter"; the NFKC it called
  Unicode 3.2 came from the running interpreter's database for code points 3.2
  left unassigned, so the list differed between 3.10 and 3.14 for such pairs. *Corrected 2026-10-24:* until then this
  paragraph said the older lowercase was taken only for the code points Unicode
  13.0 assigns and that one it leaves unassigned is kept, and a report of the same
  round said the encoder matched every interpreter's codec on every code point.
  Both described a fixed interpreter and an unfixed 3.10 only: the encoder missed
  the reading of an unfixed 3.11 or 3.12 for 40 code points and of an unfixed 3.14
  for 67. It now misses none on any of the interpreters named above, over every
  code point and every composition pair (`tests/test_value_origin_idna2003.py`,
  `tests/test_value_origin_ucd.py`).
  *Pinned by:* the published-suite differential, whose urllib.request and
  http.client clients no other ruling excuses, `tests/test_value_origin_idna2003.py`,
  `tests/test_value_origin_ucd.py`, and the client gate,
  `tests/test_value_origin_client_gate.py`: every generated value any client sends
  to, a port in every script's digits and every scheme the clients take, reads as
  a destination, never `no_destination`.
- **A value no client accepts is read conservatively** (decided by the owner,
  2026-10-24). urllib.request refuses a URL its `urlparse` refuses (a bracket that
  does not pair, a bracketed host that is no address), and the other clients refuse
  it or read another host. The core still reads the name urllib.request and
  http.client would resolve had the split gone through, beside every other reading.
  The reading errs toward holding: the name is an extra finding, `unresolved`, or
  `untrusted_source` where an untrusted result wrote the same value, and it never
  authorizes a call. `https://[::1/` reads `dns:[:`; `https://a]b@evil.test/`
  reads `dns:evil.test` and `dns:a]b@evil.test`. *Pinned by:*
  `tests/test_value_origin_stdlib_refusals.py`, and the rows `Q1-urlsplit-refusal`
  and `R33-unparseable-url`.
- **A special scheme takes its authority after any run of `/` and `\`** (R4):
  `http:evil.test`, `http:/evil.test`, `http:\\evil.test` and
  `http:///evil.test` all name `evil.test`. The special schemes are `http`,
  `https`, `ws`, `wss` and `ftp`. A non-special scheme without `//` has no host.
  `file:` and `data:` name no destination by their scheme; the host of a `file:`
  URL is read as the name urllib.request looks it up as, and the host of any URL
  with an authority as the name requests looks up on macOS (above). *Corrected
  2026-10-25:* until then this said `file:` and `data:` are never destinations;
  urlopen resolves a `file:` URL's host before it opens a local file.
  `mailto:<addr>` is a mailbox.
- **Tabs and newlines are removed from a URL**, as WHATWG and `urlsplit` remove
  them. Other whitespace counts where it lands: in a host it is no host for that
  reading; in a path, query or fragment it is percent-encoded by WHATWG, and the
  host stays readable (`https://evil.test/a b` names `evil.test`). *Pinned by:*
  `test_whitespace_in_a_url_path_leaves_its_host_readable`.
- **A host is read in every spelling a client sends it in.** Decoded before
  UTS-46, as WHATWG host parsing, urllib.request and (for unreserved escapes)
  urllib3 and requests read it; and as written, as httpx and urllib.parse send it:
  `https://ev%69l.test/` names `evil.test` and `ev%69l.test`
  (`R36-percent-host`). A character httpx or requests percent-encodes in a host
  is read encoded too (`http://a^b.example/` names `a^b.example` and
  `a%5eb.example`), urllib3's and requests' spellings for http and https only, the
  schemes they connect to (measured; requests' macOS proxy lookup of the plain
  hostname, for any scheme, is read as well, above). Each spelling keys by its registrable domain, so an escape
  inside the principal's zone (`files%2Eportal.northbank.example`) stays the
  principal's. *Pinned by:* `tests/test_value_origin_client_spellings.py`.
- **UTS-46: nontransitional, Unicode 13.0** (S-4). ß stays ß (`xn--zca`), as
  browsers resolve it. CheckBidi on; CheckJoiners on (CONTEXTJ, RFC 5892 A.1 and
  A.2); STD3 rules, CheckHyphens and VerifyDnsLength off. The mapping table
  (its STD3 statuses kept apart), bidi classes, combining marks, Joining_Type and
  the viramas are vendored from Unicode 13.0 (`_idna_data.py`), Python 3.10's
  `unicodedata` version. With all three of those flags on (`strict`), the core
  reads every row of IdnaTestV2 13.0.0 as the file does
  (`tests/value_origin_conformance/test_idna_v2.py`). A URL host that fails UTS-46
  yields `dns:<host>`, the host as written with the table's case mapping
  (`fold`), which matches only itself. Unicode domain labels are accepted and
  compared as A-labels (3.6); `R36-homoglyph-*`.
- **Case is the table's, and every lowercase a client applies is a reading.** A
  host is mapped by the UTS-46 table, never by the interpreter's `str.lower`,
  which follows its own Unicode version and applies Final_Sigma. httpx lowercases
  the whole host with `str.lower` before encoding it, and urllib3 and requests each
  label; where that reads another name that passes those clients' STD3 and hyphen
  rules, it is one more finding (`http://ΒΌΛΟΣ/` names the σ and the ς names), and
  where no client sends to a name, it is not read. A full stop the table maps to
  `.` (U+3002, U+FF0E, U+FF61) is a dot before keying, so a trailing one keys like
  a trailing `.`. *Pinned by:* `tests/test_value_origin_published_readings.py`.
- **The reading is the same on every interpreter: the findings and the wire, not
  only what blocks.** The core never calls the interpreter's `urlsplit` (its own
  copy of CPython 3.12.2's rules decides a split and whether it is a parse
  failure), and no reading consults the running interpreter's Unicode database:
  every character class (a pattern's `\w`, `\s` and `\d`, `isalpha`,
  `isspace`), case mapping (`lower`, `casefold`), normalization (NFC, and the
  IDNA 2003 codec's NFKC) and digit (`int()`) is asked of Unicode 16.0's files,
  vendored in `tests/published_vectors/upstream/` and generated into
  `_ucd_data.py`, as a given version has it (`_ucd`). The core decides as Unicode
  13.0 does, so a code point 13.0 leaves unassigned, which a newer interpreter
  calls a letter or a digit, is none to the reader; a reading that models a client
  asks that client's interpreter's version. Asked at an interpreter's own version,
  the vendored data is that interpreter's data, over every code point (measured on
  3.10.20 to 3.14.9). Every published vector, and values over the code points
  Unicode 14.0 to 16.0 added, give the same findings and the same wire after an
  empty ledger, the principal's text, a whole tool result and a tool result's
  sentence on 3.10, 3.12.2, the newest 3.12 and 3.14, Linux and macOS
  (`scripts/published_agreement.py`, which probes those code points as well), and
  the same readings on every patch release run (3.10.20 to 3.14.9). *Corrected
  2026-10-25:* this said the classes were decided by `_idna_data.py`'s assigned
  code points; they were decided by the interpreter's own data over those code
  points, and the IDNA 2003 NFKC by the interpreter's own data outright. *Pinned
  by:* `tests/test_value_origin_interpreter_independence.py` and
  `tests/test_value_origin_ucd.py`, which also refuses any reading module that
  calls a `str` method, `re` class or `unicodedata` function deciding by the
  interpreter's data.
- **A scheme token is anything before `://` made of letters, digits, `+`, `.` and
  `-`, of any length**, as urllib.parse on 3.10 and WHATWG split it. When urllib3
  refuses it as a scheme (one that is not a letter, then letters, digits, `+` and
  `-`), urllib3 connects to it as the HOST: `hej.hej://example.net` names both
  `hej.hej` and `example.net`, `0://x` names 0.0.0.0, and the call is authorized
  only if every reading is. `//host/x` is a scheme-relative reference urllib3
  sends to `host`.
- **An IPv6 literal with a zone** is read without the zone, and both ways a client
  reads a `%` in it: as RFC 6874's `%25` with the address part percent-decoded
  (urllib3, requests), and as the zone itself (urllib.parse hands it to the socket),
  so `[fe80::%31]` names fe80::1 and fe80::.
- **A URL is tried before the mailbox rule** (S-3): a value that opens with
  `scheme://`, or is a scheme-less `host/path`, is a URL even when it carries
  `@` (`R32-url-first`).
- **A `scheme://` value CPython 3.12.2's `urlsplit` refuses** (an unterminated
  IPv6 bracket), as the core's own copy of its rules decides it, is
  `parse_failure` as a whole, and every host the other readings find is a finding
  beside it (R1's shape; `Q1-urlsplit-refusal`).

### Scheme-less values

A client that guesses `http://` (curl) sends each of these where the core reads
it:

- **`host[:port]` and then a path, a query or a fragment**: a name of at least two
  labels with an alphabetic last label (`evil.test/x`, `evil.test:8080/x`,
  `ldap.example.com?special`, `pop3.example.com:100#foobar`), its labels
  possibly carrying escapes, which urllib3 sends as written. An empty port counts
  (`evil.test:/x`): urllib3 connects to the default. It is read as `http://` + the
  value, every reading included. A single-label host stays unread (`localhost/x`,
  `g?y`).
- **An address literal followed by a port, path, query or fragment**: a dotted
  quad or IPv6 in brackets, with or without a zone, in a result or an argument
  (`169.254.169.254/latest`, `10.0.0.5:80`, `[fe80::7%en1]:8443`), and with an
  empty port (`[::6]:/v1`, `[::5]://host/`), which urllib3 connects to. A zoned
  literal is read as `http://` + the value, both ways a client reads its `%`.
- **An address in any inet_aton spelling followed by a port, path, query or
  fragment**, in an argument: hex, octal, decimal and short dotted forms
  (`0xA9FEA9FE/latest`, `2852039166/latest`, `0251.0376.0251.0376/latest`,
  `169.254.43518/latest` all read 169.254.169.254; `2024/report` reads
  0.0.7.232). A tool result that is such a value records the same address: a
  whole result value is read as an argument value is (§5). *Pinned by:*
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
- **Under a shared-tenant apex a name is keyed by the whole host**:
  apexes whose hosts serve other parties' content, endpoints or tenants and that
  the PSL does not split (`google.com`, `slack.com`, `sharepoint.com`, ...; the
  vendored list is `xaidr/value_origin/_shared_tenant_data.py`). A host named
  there authorizes that host and its subdomains, never a sibling: naming
  `docs.google.com` leaves `script.google.com` to its own origin, and
  `acme.slack.com` leaves `hooks.slack.com`. A principal entry for any parent up
  to the apex authorizes; otherwise the most specific entry decides. Apexes the
  PSL already splits (`github.io`, `s3.amazonaws.com`, `storage.googleapis.com`,
  `blob.core.windows.net`) need no entry, and the test refuses one.
  *Pinned by:* `tests/test_value_origin_shared_tenant.py`.
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
  a leading-zero dotted quad read as decimal, however many zeros a part carries
  (`0000000000000000012.1.2.3` reads 12.1.2.3 beside inet_aton's 10.1.2.3, and a
  part with a non-octal digit, which inet_aton refuses, still reads as decimal),
  the IPv4 tail of an IPv6 literal read the same way, and one number above 2**32 - 1 wrapped modulo 2**32
  (`4294967296` and `0x100000000` read `0.0.0.0`; `0x1A9FEA9FE` reads
  169.254.169.254). Each is one more finding beside the inet_aton reading, public
  addresses included. *Pinned by:* `Q22-rerule-macos-decimal-quad`,
  `tests/test_differential_oracles.py` (the `_macos_reading` rows and
  `test_q22_*`).

### Mailboxes

- **A value with `@` that is not a URL is a mailbox-list candidate** (3.2). It is
  split on `,` and `;` outside `<…>` and `"…"`. Without `@` it goes to the other
  schemes or `no_destination`. An empty part (`"a@x.example; "`) is skipped.
- **An `@` that is not an address does not make an address list**. When
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
  `<` surrounds it, RFC 5322 comments around it dropped, open or closed: the
  address in `evil@x.example <`, `Bob <evil@x.example` or `<evil@x.example (ops)`
  is read, as `email.utils` and smtplib read it. Prose that mentions an address
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
- **An address list is read as RFC 5322 reads it**: comments dropped, groups
  (`Team: a@x.example, b@y.example;`), quoted local parts (`"roy a bug"@…`, and
  `"dinsdale"@…` also as `dinsdale@…`, as email.headerregistry writes it), address
  literals (`user@[192.0.2.1]`), obs-route (`<@relay:jdoe@…>`), a single-label
  domain (`user@host`), and an ASCII domain UTS-46 refuses as written, since a
  mail client sends it unvalidated. A value that is not one still names every
  angle address in it, every addr-spec when a part of it is exactly one mailbox
  or it has no whitespace at all, and the address list of each `Header:` line, as
  the legacy parser (`email.utils.getaddresses(strict=False)`) reads them. An
  addr-spec is read only where it stands alone: after the start or a separator,
  before the end or a separator. *Pinned by:*
  `tests/test_value_origin_published_readings.py`.
- **Not read, and each can be overruled:** a local part the value does not
  write, which a parser's error recovery makes up (email.headerregistry quotes
  the words before an `@` into one, `John Doe@x.example` → `"john doe"@x.example`,
  or drops the quotes inside one); and an address with other text run into it and
  no separator (`a@b c@d`, `alice@example.org )Alice(`), which is prose. Both are
  the shape of `Please send the report to bob@corp.example.`, which is not a
  recipient list.
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

### The published-suite differential

`scripts/published_differential.py` (a CI job on Linux and macOS, on 3.10,
3.12.2, the newest 3.12 and 3.14) runs every vector of WPT, CPython's urlparse,
urllib2 and email tests, IdnaTestV2 13.0.0 and 18.0.0, curl's lib1560 and Go's url
and mail tests (vendored with their licences and sources in
`tests/published_vectors/`) through httpx, urllib3, requests, urllib.parse,
urllib.request (`HTTPConnection(Request(v).host).host`, what urlopen resolves),
http.client (`HTTPConnection(urlsplit(v).netloc).host`), a WHATWG parser and the
email parsers, and fails on a destination a client reads that the core does not
and no ruling here names. A client's host is compared as the client sends it, an
escape or a backslash included, and a non-ASCII host as the socket layer encodes
it; every address the platform resolver reads a numeric host as (`inet_aton` and
`getaddrinfo`) is its own requirement, and a numeric host with a trailing dot is a
DNS name as well; a name with an empty label, whitespace or a control character is
none a resolver looks up. A client that reads no vector at all is a refusal, never
a clean run. An under-read of urllib.request or http.client is excused only where
the platform resolver refuses an empty hex part (below); no scheme-less, mailbox or
encoding ruling applies to them. *Corrected 2026-10-25:* this said both send only an
http or https URL; urllib.request also sends `ftp:` and looks up a `file:` URL's
host, and the differential reads both. The rulings it accepts an under-read under, each above: a bare
hostname or number and a single-label host before a path (V-19); `file:` and
`data:`; a URL before the mailbox rule (S-3); a mailbox is not its domain as a URL
host (3.2); an ASCII local part (3.6); an `@` that is not an address; `mailto:` is
a mailbox; a local part the value does not write; text run into an address; an
empty hex part where the resolver refuses it; and UTS-46 as S-4 pins it (IDNA
2003, IDNA 2008 without the mapping, transitional processing and newer Unicode
versions read some names otherwise, and S-4's fallback key matches only itself).
`scripts/published_agreement.py` checks that the core reads every vector the same
in every cell.

## 3. A value that names more than one destination

The core never picks one. Every destination a value names is its own finding,
and the weakest decides the wire (R1, Q1). `authority_of` returns `None` for a
value with two authorities, exactly as for a two-mailbox list, and
`extract_destinations` reports all of them. A value a client resolves under a
second name (urllib.request's userinfo host, the socket layer's IDNA 2003 name) is
two authorities too (2026-10-24): `authority_of("https://straße.example/")` is
`None`. `None` there is no single destination, never no destination: nothing in
the package calls `authority_of`, and a call naming such a value reads
`unresolved`.
*Pinned by:* `test_q1_authority_of_answers_none_for_a_value_with_two_authorities`,
`test_authority_of_answers_none_for_a_value_a_client_resolves_otherwise`, and
`tests/test_value_origin_two_readings.py`.

## 4. Trust

- A `URL_PREFIX` designation matches with no userinfo, equal lowercased schemes,
  equal hosts (case-mapped by the pinned table), equal ports after mapping 80/443
  to absent, and the pattern's path segments a segment-wise prefix of the value's.
  Query and fragment are ignored. The URL is split by the core's own rules, never
  the interpreter's `urlsplit`: a value with a backslash, a tab, a newline or
  another control, a `[` anywhere but around a whole IPv6 literal with no zone, or
  a port above 65535 never matches.
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

- **A tool result is read as an argument is, in prose too.** Each whole result
  value gets the argument reader's whole-value reading (every reading of the
  split, the scheme-less forms, S-4's fallback key, mailbox lists); and in result
  text, every whitespace-separated token and every line that holds whitespace is
  read as an argument value, and every RFC 5322 addr-spec (a quoted local part,
  comments around it) is read wherever it stands. So a destination a result names
  in a sentence or on a line of its own (`//host/x`, `[v6]:port/x`, `https:/host`,
  a mailbox at a Unicode domain) reads `untrusted_source` when a later call sends
  to it. Principal text is read by the prose patterns alone: a reading of it
  authorizes, where a reading of a result only records. The bound: a value that
  itself holds whitespace or a control character (`http://a b/`) has no edge a
  sentence or a line can mark, so it is recorded whole, as a whole result value or
  a leaf, and not from inside prose. *Pinned by:*
  `test_result_keys_contain_argument_keys_over_every_published_vector` (a whole
  value, a leaf, a sentence and a line, over every published vector).

- **`record_principal_input` writes two all-or-none units** (S-6): its
  destinations, then its key n-grams, so a long prompt's n-grams can be dropped
  without dropping the principal's addresses. `record_tool_result` is one unit,
  and atoms found past a bound are a separate unit after it.
- **Budgets.** 10,000 destination digests and 65,536 key n-grams per ledger, each
  its own budget. Key n-grams come from the first 64 KiB of principal input;
  destination atoms come from all of it. The atom pass past a bound is bounded by
  WORK: each scanned character costs 1 and each candidate examined costs 64,
  500,000 units per seam call (`ATOM_WORK_BUDGET`); a result's examined pass is
  bounded the same way at 1,000,000 units (`EXAMINED_WORK_BUDGET`). The same budget
  bounds memory: the pass past a bound builds a node's path one link at a time
  and turns it into a tuple only for a finding, charged by its length, so a value
  nested 16,000 deep costs memory in proportion to the work, never to the square
  of the depth (`test_memory_stays_bounded_at_every_nesting_depth`, 1,000 to
  16,000 deep, under 8 MiB; a `model_dump()` chain 16,000 deep peaks at 6.0 to 6.4
  MiB, `test_a_model_dump_chain_16000_deep_stays_under_the_stated_8_mib`). Strings
  a result's `model_dump()` temporaries alone hold are kept for the atom pass only
  while the budget could still scan them, and no temporary is kept for its id.
  Past the bound a value too long to read whole is stripped once per object and
  charged for the whitespace the strip scanned; the atom pass is handed what is
  left, so no character is charged twice and the time a call takes follows the
  work units (`tests/test_value_origin_cut_results.py`).
- **Observed atoms** (record only): an argument value the walk examines
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

`result_truncated` stays in the vocabulary for consumers; a call reads it no more,
since a cut result cannot vouch (below).

- **`result_unread`**: a tool result from httpx, requests, urllib3 or aiohttp is
  passed on unread, so as not to consume a stream; a destination that then traces
  to nothing reads `result_unread` (Q18).
- **`write_dropped`**: a destination write the ledger did not accept. That is a
  full ledger, or a write lost to a fault: a raising `model_dump` in the examined
  pass, a span list that does not concatenate to the text, a span item that is
  not a `Span`, a non-string input (ruling 5). Past the examined bound, a raising
  node is confined to its node and reads `result_unread`. *Pinned by:*
  `tests/test_value_origin_drop.py`.
- **A cut result cannot vouch** (decided by the owner, 2026-10-25). A tool result
  past a bound is not read whole, so what it holds is not all known, and a value
  there can name a destination no reading finds. Once the flow carries a cut
  result, a destination neither the principal nor a trusted source authorized
  reads `untrusted_source`, and blocks under ENFORCE. What the principal or a
  trusted source named keeps its authority. Until 2026-10-25 such a call read
  `result_truncated`, which did not block. *Pinned by:*
  `tests/test_value_origin_cut_results.py`.
- **The order** when the weakest finding is not `untrusted_source`: a state that
  blocks outranks every state that does not (`result_unread`, then
  `write_dropped`), then `extraction_incomplete`, `argument_bound`,
  `ledger_saturated`, `input_truncated`. An untrusted finding outranks all of
  them, a miss after a cut result included.
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
5. A tool result records every key the argument reader reads from the same text,
   the inet_aton scheme-less forms and S-4's fallback key included
   (`tests/test_value_origin_result_reader.py`, over every published vector), so a
   path in a file listing that reads as an address is recorded as that address.
6. A CIDR like `10.0.0.0/8` reads `ip:10.0.0.0`, which is `unresolved` unless
   something recorded it. `HTTP: 404` is not a URL (a space follows the colon).
7. The prose URL scan records `http:///evil.test` as `evil.test`; prose
   `http:evil.test` is recorded by the bare-host scan.
8. The RFC 3986 reading is a written-out split that reads exactly what CPython
   3.12.2's `urlsplit(...).hostname` reads, the most lenient version measured,
   so it is the same on every interpreter. Where that split refuses the WHATWG
   string, WHATWG's own bracket rule applies: a `[` must open the host and
   enclose an IPv6 literal.
9. Where that split (3.12.2's rules, written out, never the interpreter's
   `urlsplit`) refuses the WHATWG string, the value is `parse_failure` and every
   host the split finds is a finding beside it, on every interpreter alike.
10. `authority_of` returns `None` for a value with two authorities, and for one a
    client resolves under a second name (§3).
11. Two bracket over-read classes are named in the differential.
    `urlsplit-bracket-validation`: hosts CPython 3.12.2's urllib.parse reads and
    later patch releases refuse. It is checked both ways: it absorbs nothing on an
    interpreter that reads like 3.12.2 and must be needed on one that does not.
    `unbalanced-bracket`: a netloc whose brackets do not pair, which every
    urllib.parse refuses, 3.12.2 too, where the host after `@` is non-ASCII and
    keeps a backslash, so httpx refuses it as well; it must be needed on every
    interpreter, and each row is checked for that shape. *Corrected 2026-10-24:*
    the first class's predicate was any `]` urlsplit refuses, so on 3.12.2 it held
    the unbalanced-bracket rows, whose premise ("3.12.2 reads these") is false
    there, and its both-ways test was red on 3.12.2 from `fa73bff` (36 rows) with
    no pytest job on 3.12.2 to show it. CI now runs the suite on 3.12.2.
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
15. An executor job keeps S-2: a new input ends the previous implicit ledger; the
    same input scanned again is the same request (§1).
16. In an Agents SDK run's input list, strings and user messages are principal
    input; system, developer and assistant text is not recorded, and a tool output
    is recorded as an untrusted tool output (§1).
17. The first-write lock: the S22 first-write test and the all-or-none
    visibility test both stay in the suite; the second is the reliable detector of
    a ledger without its lock.
18. A result's text is read token by token and line by line as argument values
    (§5); principal text is not, so a reading only a client's parser makes of a
    principal's sentence never authorizes.
19. In a sentence or on a line, a value that itself holds whitespace or a control
    character is not recorded whole; it is, as a whole result value or a leaf (§5).
20. urllib3's and requests' host spellings are read for http and https, the only
    schemes they connect to; urllib3's parser output for another scheme is not a
    send. requests' macOS proxy lookup of the plain hostname is read for every
    scheme (§2).
21. A code point Unicode 13.0 leaves unassigned is no letter and no digit to the
    reader on any interpreter, so a scheme-less `host/path` whose host carries one
    is no destination, as on 3.10 (§2). Every such class is asked of vendored
    Unicode 16.0 data as Unicode 13.0 has it (`_ucd`); a port's digits are asked as
    Unicode 16.0 has them, since some interpreter's `int()` takes each one.
22. A `URL_PREFIX` designation never trusts a value with a backslash, a control,
    a zoned or misplaced bracket, or a port above 65535 (§4).

    Items 18 to 22, and the `flow()` limit on a leftover agent hop (§1), are
    accepted by the owner (2026-10-23).
