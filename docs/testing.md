# Testing and suite configurations

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

The suite is verified with `python -m pytest -q`.

**This page used to publish a table of pass counts, one row per install
configuration. The table is gone. It is not coming back, and the reason is the
table itself.**

Every published number in it was wrong. The `full` row said 7664; the last
branch that actually measured that configuration got 8432 — about 670 passes
behind. The `base` row said `163 skipped` <!-- suite-count-ok: retracted figure, quoted to show the page contradicting itself --> while a paragraph four screens
down explained "the 159 `base` skips", so the page contradicted itself. Underneath
both sat a third paragraph retracting a fourth number (7453) that had been
published for two minor releases against a CI job that was red the whole time.
Three separate fix-it-by-hand passes were applied to this table and it was stale
again by the next release.

That is not a discipline problem, it is a measurability problem: the table
claimed five configurations, nobody can build all five on one machine, and a
one-process `full` run has crashed the machine that comes closest. **A number
nobody can regenerate is a number nobody can check, and this one was wrong in
every row while looking like evidence.**

## The argument for deleting it rather than generating it

The obvious alternative was to have CI write the measured counts back into this
file. It was rejected for four reasons, in descending order of how much they
matter:

1. **CI cannot measure three of the five rows.** The `test` job builds exactly
   two configurations, `base` and `full` (`.github/workflows/ci.yml`). No job
   installs langchain, langgraph, deepagents, llama-index-core, crewai or
   haystack-ai. A write-back would refresh two rows and freeze three, inside a
   table newly advertising itself as machine-generated. That is worse than the
   stale table it replaced: it reads as coverage while performing none on the
   majority of its own rows.
2. **Writing back needs credentials this workflow deliberately refuses.** CI
   declares `permissions: contents: read` explicitly, and triggers on
   `pull_request` rather than `pull_request_target` with a written rationale
   about not handing fork authors a path to repository credentials. A
   self-updating doc table would buy `contents: write` on a security product's
   CI with that rationale as the currency. It also would not run on fork PRs at
   all, so the number would only refresh after merge — never in the diff the
   reviewer is reading.
3. **Even for `base` and `full`, there is no single number to write.** CI runs
   on `ubuntu-latest` across a Python matrix derived from `pyproject.toml`. The
   figures this page used to publish were CPython 3.12.2 on macOS arm64.
   Auto-writing means either picking one cell of that matrix and publishing it
   as "the" count, or publishing two counts per supported Python and rewriting
   the table every time a classifier changes in `pyproject.toml`.
4. **Nothing consumes the number.** No gate reads it, no test asserts it, no
   release step compares against it. The things that are actually contracts —
   the suite passes, `base` passes with zero third-party dependencies, the
   corpus gates exit 0 — are asserted by CI on every pull request and turn the
   run red when broken. The literal asserted nothing and went wrong anyway.

A guard keeps it deleted: `tests/test_docs_no_published_suite_counts.py` fails
if a bare `NNNN passed` literal reappears in `README.md` or `docs/*.md`. It runs
in the same `test` job as everything else, so it is red on the PR that
reintroduces the figure rather than discovered a release later. The one escape
hatch is an explicit `<!-- suite-count-ok: reason -->` on the same line, which
is a thing a reviewer sees in the diff and has to agree with.

## Where the counts are, now

In the log of every CI run, printed by the job that measured them.

| job | prints | red when |
|---|---|---|
| `pytest (py<ver>, base)` | `N passed, M skipped` — `pip install .` + `pytest`, no extras | any test fails; this job is the standing proof of the zero-dependency claim |
| `pytest (py<ver>, full)` | `N passed, M skipped` — `pip install ".[http,trace,dev]"` | any test fails |
| `corpus report (py<ver>)` | corpus table, nested-A2A FP count, intent catch rate + denominator, and the three held-out report figures | a benign gate is violated, or the nested-A2A structural FP gate is non-zero |
| `rules-in-wheel guard` | rules shipped in the built wheel | fewer than 7 rules JSON ship, or a clean-venv install cannot scan |

Two of those lines are gates and two are measurements, and the distinction is
deliberate: `corpus report` prints the intent metrics and the held-out battery
figures without gating on them, because they are numbers, not contracts. The
contract for the benign pools is in pytest — `tests/test_privilege_action.py`
asserts zero false positives on both — and that runs in the gate job.

## What CI does not run, and how to run it yourself

The three framework configurations. They need real LangChain/LangGraph/Deep
Agents, real CrewAI, or real Haystack installed, and each one moves a different
block of tests from skipped to run:

```sh
pip install ".[http,trace,dev]"                                   # the full baseline
pip install ".[langchain]" langgraph deepagents llama-index-core  # + the LangChain stack
pip install ".[crewai]"                                           # + CrewAI
pip install ".[haystack]"                                         # + Haystack
```

A one-process run of the full suite has crashed the measuring machine, so split
it:

```sh
ls tests/test_*.py | split -l 14 - /tmp/chunk_
for c in /tmp/chunk_*; do python -m pytest $(cat $c | tr '\n' ' ') -q --no-header | tail -1; done
```

**Read framework configurations against each other, not one at a time.** The
property worth checking is that installing a framework extra moves numbers only
in the configuration where that framework is installed. When the Haystack
integration landed, every other configuration gained skips and not a single
pass — that is `TestRealHaystack` skipping cleanly where `haystack-ai` is
absent. An integration that changed the pass count of a configuration whose
framework is not installed would be an integration that leaked out of its own
extra, and comparing a single configuration against its own past cannot show
you that.

## What the `base` skips are

A large skip count should never be left vague. Every `base` skip is "this
configuration does not have the thing", not a disabled test, and each one names
what to install. Counts are omitted on purpose — they move with the suite and
this page has already proved it cannot keep them honest. `python -m pytest -q
-rs` prints the current ones with their reasons.

| why | how to run them |
|---|---|
| `nano` needs `onnxruntime` + the pinned local artifact | `pip install ".[nano]"` and set `XAIDR_NANO_TEST_ARTIFACTS` |
| real Haystack not installed | `pip install ".[haystack]"` |
| needs the `[http]` extra | `pip install ".[http]"` |
| real LangChain / `langchain-core` not installed | `pip install ".[langchain]"` |
| real LangGraph (with LangChain) not installed | `pip install langgraph` |
| real CrewAI not installed | `pip install ".[crewai]"` |
| real Deep Agents not installed | `pip install deepagents` |
| `[trace]` / OpenTelemetry not installed | `pip install ".[trace]"` |
| real pyautogen not installed | `pip install "pyautogen<0.3"` |
| the async structural guard has no resolvable class seam | install any one framework above |
| real `llama-index-core` not installed | `pip install llama-index-core` |

The `nano` block dominates and is the least interesting: `[nano]` is an optional
ML signal that is off by default, and its tests need a hash-pinned artifact that
is not in the repository. The framework skips are the ones worth installing for
— they run against the real LangChain, LangGraph, Deep Agents, CrewAI and
Haystack rather than the in-repo fakes.

The two async-structural-guard skips are the ones to read rather than dismiss:
that guard asserts every sync framework seam has an async counterpart patched or
declared, and with no framework installed there is nothing for it to resolve. It
skips rather than passing vacuously, and its non-vacuity is held by two separate
tests that do not depend on this configuration.

## Reproducing any of this from an install

You cannot. The wheel and the sdist ship the `xaidr` package only, with no
`tests/` directory, so running the suite means cloning the repository. Read the
CI logs as "the maintainers run this suite and here is the run", not as "you can
run it from PyPI".

## Retraction record

Kept in place rather than deleted, because the belief is the artifact and a
reader who met one of these numbers needs to see it marked false where they met
it.

- **`base` 7603 passed / 163 skipped, `full` 7664 passed / 137 skipped, and the three framework rows** <!-- suite-count-ok: retracted figures, quoted so a reader who met them sees them marked false -->
  — published here through 1.17.0. Stale by roughly 670
  passes on the `full` row at the time of removal, and internally inconsistent
  with this page's own skip breakdown. The same `base` figure was also published
  in `docs/performance.md`; it is removed there too.
- **"no optional extras installed: 7453 passed, 6 skipped"** <!-- suite-count-ok: retracted figure, quoted so the false claim stays visible where it was made --> — published through 1.6.1. Two things
  were untrue. The number came from `.[http,trace,dev]`, not from an
  extras-free venv. And an extras-free venv did not report that at all — it
  reported **21 failures**, because httpx-dependent tests imported `httpx`
  unguarded instead of skipping. CI's `base` job had been failing on every push
  since 1.5.0 and nobody noticed, because the `corpus` job stayed green. Those
  tests now skip, which is what the job's contract always said they should do.
  The fix was never to add httpx to `base`: that job is the only standing proof
  of the zero-dependency claim, and it is what caught this.
