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
