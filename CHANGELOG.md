# Changelog

Entries are added as changes land. The release notes in the release commit body
still reconcile against the whole range (docs/releasing.md, step 1).

## Unreleased

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
  neither the principal nor a trusted source named reads `untrusted_source` and
  blocks under ENFORCE. It read `result_truncated`, which did not block. The
  principal's and trusted sources' destinations keep their authority.
- A tool result is cut wherever reading it stops before reading all of it, and
  then cannot vouch: past the leaf, size, depth and node bounds as before, and
  now past the examined pass's work budget (a call there read
  `extraction_incomplete`, which did not block), past a time bound of 2.0 seconds
  per result, at an iterator or a generator (never consumed), and at a node whose
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
- `Sensor(value_origin_wire=...)` defaults to `"v2"`, all fifteen wire values, so
  every state that decided a call's verdict reaches telemetry. It was `"v1"`,
  which withheld six; pass `"v1"` for a consumer that accepts only nine.
- A `file:` URL's host, an `ftp:` URL's host as urllib.request's FTP handler
  resolves it, and the plain hostname of a URL of any scheme are read as
  destinations: urlopen resolves the first two, and requests on macOS asks the
  system proxy check about the third, which looks it up on the older patch
  releases. A `file:` URL with a host read no destination before.
- A port written in any script's decimal digits splits a host as an ASCII port
  does, the digits Unicode 14.0 to 16.0 added included, since `int()` takes them
  on an interpreter whose Unicode has them: an unbracketed IPv6 address followed
  by such a port reads as that address.
- Readings no longer depend on the interpreter's Unicode database. Character
  classes, case mappings, normalization and the IDNA 2003 encoding come from
  Unicode 16.0's files, vendored, so a value reads the same on 3.10 and 3.14,
  including a pair of code points Unicode 16.0 composes.
