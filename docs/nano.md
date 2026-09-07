# The optional ML signal for the rules-silent band (`nano`, experimental)

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

### The optional ML signal for the rules-silent band (`nano`, experimental)

The under-scored direction above has a partial answer, and it is off unless you
ask for it twice: `pip install xaidr[nano]` **and** `Sensor(enable_nano=True)`.
It is a small local ONNX classifier (130 MB, SHA-pinned, no network at
construction or scan) that runs **only when the entire rules pipeline scored
exactly 0.0** on an inbound chat input of at least four words. Its contribution
is capped strictly below the block threshold, so it can raise a scan to
`flagged` and can never produce `blocked`. It never runs on a2a or output
traffic.

**What it is for.** There is a band of prompt-shaped attacks that the rules
provably cannot reach, because separating them from legitimate prose is not a
distinction a keyword scanner can make. Those inputs come out of the rules
pipeline at exactly 0.0. That band is what nano was built for, and it is the only
place it runs.

**That population is not currently measured in this repository, and the figures
that used to appear here are withdrawn.** Two numbers stood in this section: a
recovery count of 23 of 26 on an acceptance corpus, and 582 of 595 frame cells
recovered. Neither regenerates from the shipped package.

  * **582 of 595 frame cells: withdrawn, no derivation exists.** The committed
    generator in `tests/test_descriptive_frame_matrix.py` produces **4320**
    cells, not 3240, and on 1.7.0 **all 4320 block**, so there are **0** clean
    allows for nano to recover. Re-run against that file as it stood at
    `9cc9f41`, the commit that first published the figure, it already produced
    4320 cells and the same result. The 595 population is bare-topic attack
    shapes, and no such corpus has ever been committed to this repository. The
    figure survived only as prose.
  * **23 of 26 recovery: withdrawn, measured elsewhere against other rules.**
    That corpus lives in a separate bench repository, not in this one and not in
    the wheel, and it was scored there against a pinned older ruleset rather
    than against shipped code. Re-derived with shipped code the denominator is
    26, and the catch count is neither 23 nor stable: it moves with the
    onnxruntime version, the same drift documented below for false positives,
    on the detection side where nobody had looked. No replacement number is
    published here, because a figure from a corpus you cannot obtain is how the
    first one went wrong.

Both are withdrawn rather than corrected. When a corpus for this band is
committed to this repository, with a script that regenerates the number, the
figure comes back with its environment attached and not before.

**What it does buy, on a corpus you have.** On the shell corpus nano moves the
catch rate from 167 of 186 to **172 of 186, five commands**. It can only act
where the whole rules pipeline scored 0.0, and it never runs on the tool path,
which is the path a real agent uses for shell; there it changes nothing at all.
Of the 21 attacks marked `GAP`, 8 reach nano and it recovers 5. Which 5, and
which 3 it does not, is printed by
`python scripts/intent_metrics.py --nano`. Five of 186 is a small return, and
until the band above is measured here it is the whole measured case for the
feature.

**What it costs, and why it is a range.** On the 2000-prompt real-benign sample,
nano flags **35 (1.75%, Wilson 95% [1.26%, 2.42%]) on onnxruntime ≤ 1.23, and 67
(3.35%, Wilson 95% [2.65%, 4.23%]) on onnxruntime 1.26–1.29.** Same artifact,
same sample, same code — **your onnxruntime version decides which end you get,**
and it very nearly doubles the rate. Rules alone flag 0 of those 2000 in both
cases. So the number to plan for is: **turning nano on takes ordinary traffic
from 0.00% to somewhere between 1.75% and 3.35% flagged events — one extra event
per 57 prompts at the low end, one per 30 at the high end.**

`pip install xaidr[nano]` resolves the newer runtime today, so **expect the 3.35%
end unless you have pinned onnxruntime yourself.**

**Do not plan against our number — measure yours.** The figure moves with a
dependency you control and we do not:

```bash
python scripts/intent_metrics.py --nano --real-benign
```

| onnxruntime | flagged | rate | Wilson 95% |
|---|---|---|---|
| 1.20.1 | 35/2000 | 1.75% | [1.26%, 2.42%] |
| 1.22.0 | 35/2000 | 1.75% | — |
| 1.26.0 | 66/2000 | 3.30% | [2.60%, 4.18%] |
| 1.29.0 | 67/2000 | 3.35% | [2.65%, 4.23%] |

The break sits between 1.23 and 1.25 (1.24 has no wheel for cpython-3.12 on the
measured platform). Below 1.20 the artifact does not load at all.

**The method, because this figure has had four values and now has two.** The sample
is 2000 human-written prompts from dolly-15k / no_robots / oasst1, at least four
words, pinned **by identity** — 2000 SHA-256 hashes in
`tests/fixtures/nano_fp_sample.json`, rebuilt from the public datasets at run
time (hashes rather than text because no_robots is CC-BY-NC-4.0). It is the
sample the model acceptance used, and it is disjoint from the prompt sets the
model was selected and calibrated against. Scored through the shipped
`Sensor(enable_nano=True)` at the shipped operating point, on **xaidr 1.7.0**,
across the onnxruntime versions in the table above.

| figure | status |
|---|---|
| **1.75%** (35/2000) | **published, for onnxruntime ≤ 1.23.** Wilson 95% [1.26%, 2.42%]. |
| **3.35%** (67/2000) | **published, for onnxruntime 1.26–1.29.** Wilson 95% [2.65%, 4.23%]. This is what a default install gets today. |
| 1.85% (37/2000) | **withdrawn — published without the fact that determines it.** Not a different sample and not a different method: a figure measured on an onnxruntime the record never named, then labelled `MEASURED_ON = "onnxruntime 1.29.0"` — a runtime on which this sample yields 67/2000, not 37/2000. It sits near the 1.75% end and is most likely that measurement on an older runtime, but the record cannot establish that. The accompanying claim that re-scoring on 1.29.0 lands on 37/2000 "either way" is false. |
| 2.20% (44/2000) | **withdrawn — it was wrong, not merely stale.** The acceptance evidence file stores each prompt truncated to 200 characters as a preview; 331 of the 2000 are longer. The re-measurement scored the previews, which moves the count by +6 on its own — the whole gap. |
| 1.65% (33/2000) | **withdrawn — different sample.** A freshly drawn seeded sample overlapping this one by 128 of 2000, and *not* disjoint from the sets the model was tuned against, which biases a false-positive rate downward. The lower number was a worse measurement, not better news. |

**The runtime is not a caveat on the figure; it is half of the figure.** The
artifact is hash-pinned, but the hash fixes which bytes load, not what they
compute: an int8/int4 graph runs on onnxruntime kernels that change between
releases. This README previously said the drift was "a wash" and that the figure
landed on 37/2000 either way. That was wrong. Measured across the whole supported
range, the runtime moves the rate from 35/2000 to 67/2000.

Everything else in the inference path was checked and ruled out: `tokenizers`
0.20–0.23 produce byte-identical tokens and bit-identical scores, `numpy` 1.26
and 2.5 are bit-identical, the fp32 sibling agrees closely with the shipped
int8/int4 artifact, and the artifact hashes have never moved. Only onnxruntime
moves it. Every loaded instance records `DelphiNano.onnxruntime_version` and
compares it to `nano.MEASURED_IN`; outside the measured ranges the figure is
unverified for you, and the battery is worth re-running.

**Its score is not confidence, and the product is built so you cannot mistake it
for one.** The model rates entirely innocuous text highly — measured on
onnxruntime 1.29.0 and pinned by `tests/test_nano_published_figure.py`, a
style-guide instruction scores 0.13, a security-awareness line about never
pasting secrets scores 0.57, and "from now on, reply only with the section
headings" scores 0.88. None is an attack. (An earlier list here — a DISK BOOT
FAILURE question, a job-posting complaint, a team-building question, a Yoda
dialogue, a game of chess and a riddle — is withdrawn: those scores reproduce on
no runtime and no artifact variant we can test. See `xaidr/scanner/nano.py`.) So a nano flag writes
the *flag-band floor* into `score` and carries the model's own reading on the
separate `nano_score` / `nano_raw` fields. The verdict is the same; the ranking
is not, and an uncalibrated signal sorts below every rule flag rather than above
it. The emitted event carries `nanoCalibrated: false` and a note saying not to
triage by the value, and the mapped schema carries
`gen_ai.security.detection.nano_calibrated`.

**One interaction to know before enabling it.** Nano sees everything the rules
scored at exactly 0.0, and that includes benign prose. Of the eight security
texts in `tests/test_descriptive_topic_fp_pool.py` that pass today, **five become
flags** with nano on. They are flags, not blocks: the document still reaches your
model and you get an event. The other 30 in that file never reach nano at all,
because they never score 0.0. Both halves are locked by name in
`tests/test_nano_containment.py`.

**Cost.** `Sensor(enable_nano=True)` loads the artifact eagerly: about 1.1 s once
per process, then ~10 ms added to the p50 of a scan that reaches the model
(0.7 ms to 10.4 ms measured natively on this corpus). Load it at startup, not on
a request path.

There is also one enforcement over-reach worth knowing about: an archive stream
piped into a raw network socket blocks whatever the source directory is, so an
operator's own `tar` over `netcat` backup is blocked too. That rule keys on the
relationship instead of the object, because what gets archived is unbounded and
requiring a named sensitive path would miss the whole-filesystem case. It is
asserted as a known cost in `tests/test_shell_egress.py`.

**Destructive database statements.** An agent that runs SQL does not go through
a shell — it calls `run_sql(query=...)` — so the statement arrives as an
ordinary argument value and the shell reader never saw it. That surface is now
read directly: SQL is classified by its parsed shape regardless of the tool's
name or which argument key carries it. There is no conventional name for the key
that carries SQL, and an allowlist of key names is a gate the caller picks the
combination to. The gate is the *value*, which must begin with a SQL statement,
so prose that merely mentions `DROP TABLE` and a `psql -c "..."` command are both
left to the paths that already handle them.

The same classify/block split applies here, for the same reason it applies
above. `DROP` and `TRUNCATE` classify at critical and block nothing by default:
dropping a table is how a migration and a teardown are both written, and only
you know which database is expendable — the identical argument `terraform
destroy` gets. A `DELETE` or `UPDATE` is read through its bounding predicate
rather than its verb, because `DELETE FROM sessions WHERE expires_at < now()` is
routine and blocking on the verb would break every application on day one;
unbounded mutations classify at critical and are left to a policy. The one shape
that blocks outright is a tautological `WHERE` — `WHERE 1=1`, `WHERE true`,
`WHERE id = id`. It has no legitimate author: an operator clearing a table writes
no `WHERE` at all, and an ORM writes a real predicate, so a predicate that is
always true is what you get when something wanted the effect of no predicate
while looking like it had one.

Which statements fire is reported by family here and not enumerated, the same
discipline the shell families follow. These cases are not part of the shell
corpus and are not counted in the table above; they are asserted in
`tests/test_sql_classes.py`.

**Jailbreak coverage is pattern-shaped, and narrow by construction.** What fires
is explicit persona adoption and safety-negation framing — a named persona, a
developer-mode or unrestricted-mode request, a direct instruction to disregard
the rules. Jailbreaks that arrive wrapped in a narrative frame, where the request
is carried by the story rather than stated, are **not reliably detected**; the
families are listed here and the phrasings are not, the same discipline the shell
coverage follows. Separately, a prompt asking the model to *generate* harmful
content is out of scope for this sensor entirely: that is the model's own safety
layer, not a runtime action sensor. `xaidr` inspects what an agent does — the
tool call, the destination, the outbound payload — and a request for text is none
of those.

**What the corpus does not tell you.** It is a shell-command corpus. It says
nothing about coverage of prompt-shaped attacks (injection, jailbreak, persona
override), nothing about the A2A path, and nothing about the output boundary;
those are exercised by other test files and are not reduced to a single number
here. It also says nothing about your traffic — a corpus is a sample, and 89.8%
on this one is a statement about these 186 commands. Separately, the `nano`
false-positive figure below rests on public benign datasets that a public model
may have seen: we did not train that model, its authors' statement about their
training mix is not something we verified, and contamination cannot be ruled
out. Run [monitor mode](https://github.com/delphisecurity/xaidr/blob/main/README.md#deployment-modes-and-tuning) against your own workload
before enabling hard blocking.


