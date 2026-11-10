# Changelog

Entries are added as changes land. The release notes in the release commit body
still reconcile against the whole range (docs/releasing.md, step 1).

## Unreleased

- The egress attestation seam, S14 `SensorExtension.attest_egress(view)`: once per
  outbound request on every HTTP path xaidr dispatches (httpx sync and async and
  requests under `protect()`, and `ProtectedHttpClient`'s five verbs), after that
  request's own scan and destination check and before it is sent, an extension
  receives an `EgressView` (method, host, the enforcement mode, the value-origin
  mode, the scans bound to the request, the body's SHA-256, the sensor version;
  no content) and returns headers, which the sensor adds under the add-only rule.
  Nothing runs, and no digest is computed, when no extension overrides the hook.
  A `data=` or `files=` body sent through `protect_http` without `protect()`
  carries no attestation. Traffic over `urllib3`, `urllib`, `aiohttp` and `httpx2`
  (the OpenAI and Anthropic SDKs' current lines, and `mcp` 2.x) is not dispatched
  by xaidr and carries none.
- Two scans bind to a request: the scan of its own bytes, and on an MCP
  `tools/call` body (mcp 1.x, over httpx) the tool-call scan with the same tool
  name and arguments hash, taken once from a per-sensor table of 256 entries and
  300 seconds. The view orders them strictest found first.
- `ScanResult.found_action`: what a block-mode sensor returns for the same input,
  before monitor softening and before any S6 transform, carried on every result
  and read onto the attestation as `found`. A monitor sensor's attestation says
  `found=blocked` for a call it let through as `flagged`; an enforcing gateway
  refuses that call. It applies the documentary-prose cap on tool arguments as
  block mode does, never carries a value-origin block in 1.22.0, and is not part
  of a result's equality.
- `ScanResult.scan_id`: the telemetry event's `scanId`, minted once per scan and
  put on the result on every exit of `scan`, `scan_a2a` and `scan_tool_call`, so
  a caller can name the row its result belongs to.
- `ScanResult.threats` and the event key `threats`: one `{rule, category, score,
  layer}` per rule, in the order of `rules`, at most 50 with `threatsCut` naming
  how many more there are. `layer` is `l1`, `l2`, `dlp`, `composite`, `nano`,
  `authz` or `gate`. Never the matched text.
- Every `tool_call` event carries `parentScanId`, the `scanId` of the most recent
  input scan in the execution context (absent means not evaluated), and
  `traceParent` from the active OpenTelemetry span when one is active or from the
  new `scan_tool_call(..., parent_context=...)` keyword, never from an inbound
  header. The refusal emitters (fail-closed, an open circuit, an S5 gate, a
  not-scannable input, a scan fault, a destination block) carry the same
  `provenance` block the main path carries.
- S7 `SensorExtension.enforcement_policy()` is wired, harden-only (#13, #50): an
  extension's enforcing policy upgrades a non-enforcing configured one, a
  non-enforcing answer never weakens an enforcing one, a tie keeps the configured
  policy, `shadow_mode` still collapses to monitor, and a non-policy answer raises
  at construction, under `shadow_mode` too.
- S12 `outbound_headers` merging (#14, #41): an extension adds headers to
  `ProtectedHttpClient` requests; it never overwrites one the sensor, the caller,
  the client's defaults or an earlier extension wrote. A fault, a non-Mapping
  return, a non-str name or value, a name that is not an HTTP token or a value
  outside printable ASCII drops that extension's headers, logged once; under
  `fail_closed=("controls",)` the fault is a verdict (monitor records and
  proceeds, block refuses). A header collision degrades and never refuses.
- `ProtectedHttpClient` body verbs run the scan, then the headers, then the
  attestation, then send; a refused request builds no headers. `protect_http`
  together with `protect()` scans and attests one request once (it was scanned
  twice, under two scan ids): the client marks what it did and the send seam does
  only what is left, so GET and DELETE responses, `base_url`-relative
  destinations and `data=` bodies keep their scan at the send seam.
- The run-tree keys (`runTree`, `runRootId`, `runTaskId`, `runParentId`,
  `runNode`, `runNodePath`, `runStep`, `runSeq`, `runSource`, `toolCallId`) ship
  in a release for the first time, under `protect()` with LangChain or LangGraph.
- The rule bundle loader: `Sensor.load_rule_bundle(bundle)` adopts a complete rule
  set (the seven packaged rule files as parsed JSON under an integer `version`)
  whole or not at all, the way `set_policy` adopts a policy; a rule that would
  not load refuses the whole bundle and the rules in force keep scanning. S15
  `SensorExtension.rule_bundle()` hands one in at attach. While a bundle is in
  force its version rides every event as `bundleVersion`. Open never fetches or
  verifies a bundle.
- The telemetry schema stays at `0.3.0`: every key this release adds is additive.
- Value origin records: every tool-call event carries `valueOrigin`, where the
  call's destination came from, and value origin never changes an action.
  `Sensor(value_origin=...)` takes `"record"` (the default) or `"off"`.
  Value-origin enforcement is available in a later release: asking for it in any
  spelling (`"enforce"`, `"ENFORCE"`, `Mode.ENFORCE`), from `Sensor`, `protect()`,
  `delphi_middleware()`, `delphi_hooks()`, `value_origin.validate_mode` or
  `value_origin.should_block`, raises `xaidr.ValueOriginEnforcementUnavailable` (a
  `ValueError`). A value that is not a mode raises `ValueError`. `value_origin`
  passed beside an existing `sensor=` is refused rather than ignored, as is an
  `enforcement_mode` to `protect()` that is no mode. L1 and every other
  enforcement are unchanged.
- `authority_of` returns `None` for a value that real clients send to more than
  one place. `authority_of("https://corp.example@evil.test/")` is `None`, where it
  was `dns:evil.test`: httpx sends it to `evil.test`, and urllib.request resolves
  the name `corp.example@evil.test`. `authority_of("https://straße.example/")` is
  `None`, where it was `dns:xn--strae-oqa.example`: UTS-46 encodes the host as
  `xn--strae-oqa.example`, and the socket layer as `strasse.example`.
  `authority_of("https://a‍b.example/")` (a zero-width joiner in the host) is
  `None`, where it was `dns:a‍b.example`: the socket layer drops the joiner
  and resolves `ab.example`. `None` means the value has no single destination;
  `extract_destinations` lists every destination it names. Nothing in xaidr calls
  `authority_of`, and a tool call naming such a value reads `unresolved`.
- After a tool result too long to read whole, a tool call to a destination
  neither the principal nor a trusted source named reads `untrusted_source`. It
  read `result_truncated`. The
  principal's and trusted sources' destinations keep their authority.
- A tool result is cut wherever reading it stops before reading all of it, and
  then cannot vouch: past the leaf, size, depth and node bounds as before, and
  now past the examined pass's work budget (a call there read
  `extraction_incomplete`, which did not block), past a work meter that counts
  the label-by-label work long non-ASCII hosts take, at an iterator or a generator (never consumed), and at a node whose
  `model_dump()` or `str()` raises (the whole result read `write_dropped`; the
  rest of it is now read).
- No tool-result node is read as empty. bytes inside a result are read as their
  text, an object of a type value origin does not recognise as its `str()`, a
  `deque`, a mapping view and any other sequence member by member, and a key of
  any type. They read as having no text before.
- Under `xaidr.protect()`, CrewAI and Haystack tool results are recorded (as the
  model is handed them, unscanned and untrusted); they were not recorded at all.
  The Agents SDK seam also records the `str()` of a return value it hands the
  model.
- No verdict depends on machine load. What a scan reads is decided by work: the
  L1 rule loop always runs every rule, a long input is read in at most two windows
  (`MAX_SCAN_WINDOWS`; it was eight under a 1.0 s budget, which in practice let
  the clock decide), and a tool result's reading stops where its work meter is
  spent. The wall-clock limits are 120 s backstops (they were 0.5 s, 1.0 s, 1.0 s
  and, for a tool result, 4.0 s); when one fires the verdict carries its own
  reason: `LLM04_scan_budget_exceeded` or `LLM04_pathological_pattern` on the
  scan, `valueOriginBackstop` on a tool-call event. A 90 000-character benign
  document that read `flagged` on a loaded host now reads as it does idle. What
  that work costs in time is a measured figure per path, on the CI runners and
  stated in `docs/performance.md`; the tests assert the work as counts, and one
  timing check per path holds about 1.5 times the runners' worst case.
- requests on macOS: the name the older patch releases' proxy check looks up,
  the hostname less a trailing `:digits` (`http://[fd00:ec2::254:80]/` looks up
  `fd00:ec2::254`), is read as a destination beside the hostname. That name
  is given wherever its host is given: the principal who types
  `http://[::1]:8080/` gives `:` too, and a `URL_PREFIX` designation on
  `http://[2001:db8::1]/docs/` trusts its reads. Only that truncation of an ASCII
  host qualifies; a name reached by IDNA or a case mapping stays one the principal
  never gave. `authority_of` answers `None` for such a URL, as for any value with
  two readings.
- `Sensor(value_origin_wire=...)` defaults to `"v2"`, all fifteen wire values, so
  every state that decided a call's verdict reaches telemetry. It was `"v1"`,
  which withheld six; pass `"v1"` for a consumer that accepts only nine.
- A `file:` URL's host, an `ftp:` URL's host as urllib.request's FTP handler
  resolves it, and the plain hostname of a URL of any scheme are read as
  destinations: urlopen resolves the first two, and requests on macOS asks the
  system proxy check about the third, which on the older patch releases looks
  up that hostname less a trailing `:digits`; that name is read as well. A
  `file:` URL with a host read no destination before.
- A port written in any script's decimal digits splits a host as an ASCII port
  does, the digits Unicode 14.0 to 16.0 added included, since `int()` takes them
  on an interpreter whose Unicode has them: an unbracketed IPv6 address followed
  by such a port reads as that address.
- Readings no longer depend on the interpreter's Unicode database. Character
  classes, case mappings, normalization and the IDNA 2003 encoding come from
  Unicode 16.0's files, vendored, so a value reads the same on 3.10 and 3.14,
  including a pair of code points Unicode 16.0 composes.
