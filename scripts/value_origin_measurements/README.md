# How the "before M8" measurements were made (PROGRESS.md items 2 and 3)

Run from the repository root with `PYTHONPATH=.` and the dev extra installed.

- `fp_corpus.py OUT.json [SITE_PACKAGES ...]` builds the benign corpus. It
  walks `/etc`, `/private/etc`, `/opt/homebrew/{etc,share/doc,share/man,Cellar}`
  and `/usr/share/man`, plus the given site-packages directories. It skips test
  directories (adversarial by design), anything under this project or the
  Delphi repos, and personal logs. It extracts every URL host and every token of
  the affected shapes:
  - a dotted quad with a leading-zero part;
  - an IPv6 literal with a leading-zero IPv4 tail;
  - a number above 2**32-1.

  The corpus depends on the machine. The 2026-10-04 run (macOS, Homebrew)
  read 24,466 files, and its token list is committed in
  `docs/evidence/macos-widening-fp-corpus.json`.
- `fp_measure.py CORPUS.json OUT.json` runs each case through the current core
  and through the same core with `_authority._macos_readings` switched off. A
  case changes if its destination readings, url_parse address class, or
  `scan_tool_call` action differ. Every changed case is written, named.
- `q13_block_rate.py` gives Q13's block rate: the share of tool calls whose
  wire is `untrusted_source` under ENFORCE (`should_block` is not wired). It
  covers the 456-row shell corpus by bucket, the adversarial corpora via
  `tests/outside/drivers/c11_oracle.py`, and the conformance flows'
  `expected.jsonl`.
