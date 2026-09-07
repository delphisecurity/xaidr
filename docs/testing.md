# Testing and suite counts

_Part of the [xaidr](https://github.com/delphisecurity/xaidr/blob/main/README.md) documentation._

The suite is verified with `python -m pytest -q`.

proves the headline claim: the core suite runs with **zero third-party
dependencies**. The suite covers the public scan APIs, wrappers, policy,
provenance, reporters, telemetry schema, and resilience behavior.

A pass count means nothing without the configuration that produced it, because
whole test classes only exist when a framework is importable. All four are given
rather than the flattering one, measured on this commit, CPython 3.12.2 on
macOS 26.6 / arm64:

| configuration | install | result |
|---|---|---|
| `base` (CI job) | `pip install .` && `pip install pytest` | **7566 passed, 159 skipped** |
| `full` (CI job) | `pip install ".[http,trace,dev]"` | **7623 passed, 137 skipped** |
| `full` + the LangChain stack | &nbsp;&nbsp;+ `".[langchain]" langgraph deepagents llama-index-core` | **7670 passed, 95 skipped** |
| `full` + CrewAI | &nbsp;&nbsp;+ `".[crewai]"` | **7636 passed, 124 skipped** |
| `full` + Haystack | &nbsp;&nbsp;+ `".[haystack]"` | **7654 passed, 106 skipped** |
| `corpus` (CI job) | `pip install .` && `python scripts/corpus_report.py` | benign gates **PASS**, exit 0 |
| `corpus` (CI job) | &nbsp;&nbsp;&nbsp;&nbsp;then `python scripts/intent_metrics.py` | catch rate + denominator printed into the log; reported, not gated |

The LangChain-stack row is the one that exercises the real LangGraph `ToolNode`
return contract and the real Deep Agents import-order check; the CrewAI row is
what proves those two changes left the CrewAI seam alone. Framework versions in
that measurement: langchain 1.4.0, langchain-core 1.6.2, langgraph 1.2.11,
deepagents 0.7.13, llama-index-core 0.14.24, crewai 1.15.20, haystack-ai 3.1.1.

**Read the four framework rows against each other, not one at a time.** Adding
the Haystack integration moved the pass count in exactly one of them: every
other config gained 31 skips and not a single pass, which is the new
`TestRealHaystack` class skipping cleanly where `haystack-ai` is absent. A
framework integration that changed a number in a config where its framework is
not installed would be an integration that leaked out of its own extra.

**A correction, because this paragraph was wrong through 1.6.1 and the CI it
described was red.** It claimed "no optional extras installed: 7453 passed, 6
skipped". Two things were untrue. The number came from `.[http,trace,dev]`, not
from an extras-free venv. And an extras-free venv did not report 7453 passed —
it reported **21 failures**, because httpx-dependent tests imported `httpx`
unguarded instead of skipping. CI's `base` job had been failing on every push
since 1.5.0 and nobody noticed, because the `corpus` job stayed green. Those
tests now skip, which is what the job's own contract always said they should do;
the fix was never to add httpx to `base`, since that job is the only standing
proof of the zero-dependency claim and is what caught this.

What the 159 `base` skips are, since a large skip count should never be left
vague. Every one of them is "this configuration does not have the thing", not a
disabled test — each line names what to install to run it. Grouped by what is
missing, and the group counts sum to 159 rather than to a subset:

| skips | why | how to run them |
|---:|---|---|
| 49 | `nano` needs `onnxruntime` + the pinned local artifact | `pip install ".[nano]"` and set `XAIDR_NANO_TEST_ARTIFACTS` |
| 31 | real Haystack not installed | `pip install ".[haystack]"` |
| 20 | needs the `[http]` extra | `pip install ".[http]"` |
| 14 | real LangChain / `langchain-core` not installed | `pip install ".[langchain]"` |
| 14 | real LangGraph (with LangChain) not installed | `pip install langgraph` |
| 12 | real CrewAI not installed | `pip install ".[crewai]"` |
| 11 | real Deep Agents not installed | `pip install deepagents` |
| 2 | `[trace]` / OpenTelemetry not installed | `pip install ".[trace]"` |
| 2 | real pyautogen not installed | `pip install "pyautogen<0.3"` |
| 2 | the async structural guard has no resolvable class seam | install any one framework above |
| 1 | real `llama-index-core` not installed | `pip install llama-index-core` |
| 1 | superseded duplicate | — |

The nano block dominates and is the least interesting: `[nano]` is an optional
ML signal that is off by default, and its tests need a hash-pinned artifact that
is not in the repository. The 75 framework skips are the ones worth installing
for — they are the tests that run against the real LangChain, LangGraph, Deep
Agents, CrewAI and Haystack rather than the in-repo fakes.

The two async-structural-guard skips are the ones to read rather than to
dismiss: that guard asserts every sync framework seam has an async counterpart
patched or declared, and with no framework installed there is nothing for it to
resolve. It skips rather than passing vacuously, and its non-vacuity is held by
two separate tests that do not depend on this configuration.

That figure is a **source-tree** claim, not something you can reproduce from
what you installed: the wheel and the sdist ship the `xaidr` package only, with
no `tests/` directory, so verifying it means cloning the repository. It is
stated here because the number is a fact about the project, but you should read
it as "the maintainers run this suite", not as "you can run it from PyPI".

