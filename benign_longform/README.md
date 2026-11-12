# Long-form benign corpus

24 realistic long benign inputs, 90 000 to 900 000 characters, six shapes. It
exists to measure the false-positive cost of the `bounds` fail-closed group on
the one bound no committed pool could reach.

## Why this corpus

The `bounds` group refuses an input that defeated a parser bound. The widest of
those bounds is the L1 scan window at `L1_MAX_SCAN_CHARS = 100 000`.

**The longest benign item in any other committed pool is 3 241 characters** —
31× short of the cap. Measured across `asi_battery/`, `heldout/`,
`benign_toolcalls/`, `benign_a2a/` and `tests/fixtures/shell_corpus.json`:

```
  asi.benign             max_len=182
  benign_a2a             max_len=3241
  heldout.benign         max_len=159
  shell.benign           max_len=50
  shell.prose            max_len=254
  shell.template         max_len=44
```

So "0 benign items block on the over-length path", read off those pools, would
not be a measurement. It would be absent test data, and shipping the group on
the strength of it would be the blind-population failure
`benign_a2a/README.md` documents.

## What's here

| File | What it is |
|---|---|
| `manifest.json` | **committed.** Per item: id, shape, length, sha256 of the text |
| `last_run.json` | **not committed** (gitignored, like every other pool's) |
| `../scripts/longform_bounds.py` | pins the wall clock so the numbers below are a property of the text, not of the box |
| `../scripts/build_benign_longform.py` | the generator — deterministic, seeded |
| `../scripts/benign_longform_report.py` | regenerates, verifies hashes, measures |
| `../tests/test_benign_longform.py` | the gates |

**The text is not committed, and the manifest is why that is safe.** 24 items
totalling 10 100 008 characters is 10.5 MB of JSONL against a tracked tree that
is otherwise 4.4 MB — committing it would more than triple the repository, for
bytes that are reproducible from a 4.1 KB manifest. (Measured 2026-09-20; a
reader can reproduce the tracked-tree figure with
`git ls-files -z | xargs -0 du -ch | tail -1`.)
What is committed is the generator plus a sha256 per item, and
`test_manifest_pins_the_generated_corpus` regenerates and checks every hash —
so an edit to a word list fails loudly instead of quietly detaching the numbers
below from the text that produced them. Materialise the corpus with
`python scripts/build_benign_longform.py --write-corpus`.

### The six shapes

Chosen because they are how a real agent actually ends up holding six figures
of characters, and because they differ in ways the scanner cares about — prose
versus structured, punctuation-dense versus not, one document versus many
records.

| Shape | Represents |
|---|---|
| `policy_document` | a policy or contract pasted in for summarisation |
| `kubectl_dump` | a `kubectl get pods -o json` result handed back to the agent |
| `thread_dump` | a JVM thread dump pasted in for triage |
| `support_transcript` | a long multi-turn support conversation |
| `csv_export` | an order-line CSV returned by a reporting tool |
| `log_tail` | an application log tail handed over to diagnose |

No item is padded with repeated filler. Padding with one paragraph repeated 400
times trips `LLM04` repetition detection, which would make the pool measure the
generator rather than the bound.

### The four sizes are four different questions

| Size | Question |
|---|---|
| 90k | **control.** Under the cap; must behave identically with the group open or closed |
| 150k | Over the cap, inside the two-window coverage — **covered completely** |
| 400k | Past `(100000 − 512) + 100000 = 199 488`, so the **window cap** stops the scan on any machine |
| 900k | The same, further past it |

Every row is defined by the window count (`MAX_SCAN_WINDOWS = 2`), on any
machine: since 2026-11-01 the wall clock is a backstop that records its own rule
when it fires, and decides nothing else (see
[the boundary](#the-boundary-is-the-window-count)). Until then the cap was eight
windows under a 1.0 s budget, the 400k row read "still inside the eight-window
coverage", and where the clock landed decided the band between.

---

## Finding 1 — "long" and "not fully read" are different facts, and only one of them is a bound fault

`LLM01_oversized_input` fires on `len(prompt) > L1_MAX_SCAN_CHARS` **and nothing
else**. It is therefore on every input past the cap, including the ones the
windowed scan then covers completely. A 150 000-character contract is two
windows — fully read — and carries the identical rule to a 900 000-character
one whose tail is never reached.

The naive design of `bounds` refuses on that rule. Measured on this pool, over
the 9 items that are clean at the default posture:

```
NAIVE   (refuse on LLM01_oversized_input)        refused-and-unread 4   refused-but-FULLY-READ 2   allowed 3
SHIPPED (refuse on LLM01_input_tail_unscanned)   refused-and-unread 4   refused-but-FULLY-READ 0   allowed 5
```

**Two fully-read documents refused under the naive signal; zero under the
shipped one, with no loss of coverage on the truncated items.** (At eight windows,
until 2026-11-01, the counts were 2 / 4 / 3 and 2 / 0 / 7.) That is why
`scanner/l1.py` carries a second rule, `LLM01_input_tail_unscanned`, fired
by `LocalScanner._scan_tail` when the windows run out before the text does, and
why `_BOUND_SIGNAL_RULES` in `sensor.py` names that one and not the other.

`tests/test_benign_longform.py::test_a_fully_read_long_document_is_NOT_refused`
is the gate; it fails against the naive signal.

### The measured run

```
  items                                    24
  window coverage limit = 199,488 chars (two windows)
  over the 100,000-char cap              19
    ...FULLY covered by the windowed scan  6
    ...tail never read                     13

  clean at the DEFAULT posture             9
  scoring on CONTENT at the default        15   (excluded from the bounds cost — see finding 2)

  THE BOUNDS COST, over default-clean items only
    refused, tail genuinely unread          4   (the group working as designed)
    refused, FULLY READ                     0   <- false positives
    not refused                             5
```

**These numbers are the same on any machine.** The report still runs with the
clocks pinned (`scripts/longform_bounds.py`), and since 2026-11-01 that changes
nothing: the window count decides every item's bucket at runtime too. The one
figure the group is justified by, **refused-but-fully-read, is 0.**

### The boundary is the window count

At runtime an L1 scan reads what its work limits allow and nothing decides by
the clock: every rule runs over at most 100 000 characters, and a long input is
read in at most `MAX_SCAN_WINDOWS` (2) windows. The three wall-clock limits,
`_L1_SCAN_BUDGET_SEC` (the rule loop), `_L1_RULE_SLOW_SEC` (one pattern) and
`TOTAL_SCAN_BUDGET_SEC` (the window walk), are 120 s backstops, far above the
worst case of that work on the CI runners (`docs/performance.md`). When one fires the verdict carries
its own rule (`LLM04_scan_budget_exceeded`, `LLM04_pathological_pattern`), so a
backstop never changes a verdict silently
(`tests/test_deterministic_bounds.py`). An item under the cap reads the same on
an idle host and a busy one, and an item past 199 488 characters has an unread
tail on every machine.

What a whole scan of the worst input costs at two windows is a measured figure,
on the CI runners and here (`docs/performance.md`), not a limit. *Corrected
2026-11-02:* this called two windows a calibration that kept the worst scan within
the engine's ~2 s per-scan bound, from a measurement on one machine (2.08 s of CPU
on its slowest interpreter, 2.65 s at three windows). On the CI runners the same
work took 2.75 to 3.80 s; the bound held only where it was measured.

*Until 2026-11-01* those limits were 0.5 s, 1.0 s and 1.0 s and decided how much
was read, so the same document could be refused on a loaded host and allowed on
an idle one, even under the cap. On a GitHub ubuntu-latest runner, 2026-09-20,
`LF-*-90k` (under the cap) read `LLM04_scan_budget_exceeded` and every over-cap
item `LLM01_input_tail_unscanned`, and
`test_oversized_and_tail_unread_are_different_signals` failed its own vacuity
guard. This section said so as a caveat for operators; the change makes it no
longer true.

## Finding 2 — realistic long operational text scores on content, independent of this work

**15 of the 24 items score at the DEFAULT posture**, with no group closed and
nothing to do with `bounds`:

| Item | Rules |
|---|---|
| `LF-kubectl_dump-*` | `LLM06_outbound_exfil_suspicious_dest`, `LLM06_phone`, `DLP_phone`, `INTENT_exfiltrate_data` |
| `LF-support_transcript-*` | `INTENT_exfiltrate_data` |
| `LF-log_tail-*` | `INTENT_exfiltrate_data` |
| `LF-policy_document-150k/400k/900k` | `INTENT_exfiltrate_data`, `INTENT_destroy_resources`, `INTENT_escalate_privileges`, `COMPOSITE_trust_exploit_data_access`, `COMPOSITE_cascading_failure`, `authority_override` |

**The `policy_document` rows fire on text in the first two windows.** A pasted
policy document discussing data handling, privilege and deletion trips six rules
on its own content — the same finding as the rows below. It is excluded from
the bounds cost for the same reason as the others.

Two distinct causes, both length-correlated:

* **`INTENT_exfiltrate_data` is an L2 co-occurrence rule** — it pairs an action
  word with a target word. In a 90 000-character log tail, *some* action word
  and *some* target word co-occur with near certainty (`action=relay
  target=records` in the log tail, `action=export target=Data` in the
  transcript). The longer the honest document, the likelier the pair. This
  fires on all fifteen scoring items.
* **DLP digit-run patterns span whitespace.** The SSN and phone patterns match
  across a newline, so a log line ending in a bare number followed by a line
  starting with a timestamp matched `DLP_ssn`. The generator now terminates such
  lines with punctuation — but real logs do not, and a real `kubectl -o json`
  really does carry 9-digit `resourceVersion` values.

**These are excluded from the bounds cost above** and counting them in it would
blame `bounds` for refusals it did not cause. They are recorded here because
they are a genuine finding about long input that this corpus is the first thing
in the repo able to see — and because a future reader comparing these numbers
to the clean-pool numbers will otherwise assume the pool is broken.

Neither is fixed by this work. Both are candidates for their own measurement.

## Reproducing

```sh
PYTHONPATH=. python scripts/build_benign_longform.py        # re-pin the manifest
PYTHONPATH=. python scripts/benign_longform_report.py       # verify + measure
PYTHONPATH=. python -m pytest tests/test_benign_longform.py -q
```

The report refuses to measure if the manifest and the generator disagree.
