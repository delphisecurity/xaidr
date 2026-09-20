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

So "0 benign items block on the over-length path" was never a measurement. It
was absent test data, and shipping the group on the strength of it would have
been the eighth instance of the blind-population failure
`benign_a2a/README.md` documents.

## What's here

| File | What it is |
|---|---|
| `manifest.json` | **committed.** Per item: id, shape, length, sha256 of the text |
| `last_run.json` | **not committed** (gitignored, like every other pool's). The wall-clock caveat below is exactly why: this pool's results are machine-dependent in the 150 KB–800 KB band |
| `../scripts/build_benign_longform.py` | the generator — deterministic, seeded |
| `../scripts/benign_longform_report.py` | regenerates, verifies hashes, measures |
| `../tests/test_benign_longform.py` | the gates |

**The text is not committed, and the manifest is why that is safe.** 24 items
totalling 10 million characters is 25 MB of JSONL against a repo that is
otherwise 8 MB. What is committed is the generator plus a sha256 per item, and
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
| 150k | Over the cap, two windows out of eight — **covered completely** |
| 400k | Over the cap and near the WALL-CLOCK budget rather than the window count |
| 900k | Past `8 × (100000 − 512) = 795 904`, so the **window cap** stops the scan on any machine |

---

## Finding 1 — "long" and "not fully read" are different facts, and only one of them is a bound fault

`LLM01_oversized_input` fires on `len(prompt) > L1_MAX_SCAN_CHARS` **and nothing
else**. It is therefore on every input past the cap, including the ones the
windowed scan then covers completely. A 150 000-character contract is two
windows out of an eight-window budget — fully read — and carried the identical
rule to a 900 000-character one whose tail was never reached.

The first design of `bounds` refused on that rule. Measured on this pool, over
the 12 items that are clean at the default posture:

```
NAIVE   (refuse on LLM01_oversized_input)        refused-and-unread 7   refused-but-FULLY-READ 2   allowed 3
SHIPPED (refuse on LLM01_input_tail_unscanned)   refused-and-unread 7   refused-but-FULLY-READ 0   allowed 5
```

**Two fully-read documents refused under the naive signal; zero under the
shipped one, with no loss of coverage on the truncated items.** That is why
`scanner/l1.py` now carries a second rule, `LLM01_input_tail_unscanned`, fired
by `LocalScanner._scan_tail` when the windows run out before the text does, and
why `_BOUND_SIGNAL_RULES` in `sensor.py` names that one and not the other.

`tests/test_benign_longform.py::test_a_fully_read_long_document_is_NOT_refused`
is the gate; it fails against the naive signal.

### The measured run

```
  items                                    24
  over the 100,000-char cap              19
    ...FULLY covered by the windowed scan  4
    ...tail never read                     15

  clean at the DEFAULT posture             12
  scoring on CONTENT at the default        12   (excluded from the bounds cost — see finding 2)

  THE BOUNDS COST, over default-clean items only
    refused, tail genuinely unread          7   (the group working as designed)
    refused, FULLY READ                     0   <- false positives
    not refused                             5
```

### The caveat that must ship with the number

**The boundary is a wall-clock budget, not a length.** `TOTAL_SCAN_BUDGET_SEC`
is 1.0s and `MAX_SCAN_WINDOWS` is 8, and for anything between roughly 150 KB
and 800 KB it is the clock that decides, not the window count. Two items of
identical length in this pool land on opposite sides of it:

```
LF-csv_export-150k      150,013  oversized_input                        -> flagged (covered)
LF-support_transcript-150k 150,091  oversized_input,input_tail_unscanned -> blocked (truncated)
```

So the same document can be refused on a loaded host and allowed on an idle
one. That is a real property of `bounds` in this range and an operator enabling
it needs to know: under the cap is deterministic, past ~800 KB is
deterministic, and the band between them depends on how busy the machine is.

## Finding 2 — realistic long operational text scores on content, independent of this work

**12 of the 24 items score at the DEFAULT posture**, with no group closed and
nothing to do with `bounds`:

| Item | Rules |
|---|---|
| `LF-kubectl_dump-*` | `LLM06_outbound_exfil_suspicious_dest`, `LLM06_phone`, `DLP_phone`, `INTENT_exfiltrate_data` |
| `LF-support_transcript-*` | `INTENT_exfiltrate_data` |
| `LF-log_tail-*` | `INTENT_exfiltrate_data` |

Two distinct causes, both length-correlated:

* **`INTENT_exfiltrate_data` is an L2 co-occurrence rule** — it pairs an action
  word with a target word. In a 90 000-character log tail, *some* action word
  and *some* target word co-occur with near certainty (`action=relay
  target=records` in the log tail, `action=export target=Data` in the
  transcript). The longer the honest document, the likelier the pair. This
  fires on all twelve.
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
