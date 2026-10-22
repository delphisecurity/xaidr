# Run-tree build evidence (2026-10-19)

Raw output from the build of `feat/run-tree` against `docs/run-tree-spec.md`.
Every file is a command's own output. Nothing is retyped.

Three environments, all made with `uv`:

- **pins**: Python 3.12, langchain-core 1.6.1 / langchain 1.4.1 / langgraph 1.2.12 / langgraph-prebuilt 1.1.0. These are the CI real-frameworks pins.
- **pins310**: the same pins on Python 3.10.
- **latest**: Python 3.12, langchain-core 1.6.12 / langchain 1.4.6 / langgraph 1.2.16 / langgraph-prebuilt 1.1.1.

The base CI config (no third-party packages) ran in a fourth venv. Every tree
run set `PYTHONDONTWRITEBYTECODE=1` and `PYTHONPATH` to the worktree.

| File | What it shows |
|---|---|
| `red_at_head_summary.txt` | `tests/test_run_tree.py` written first and run before any implementation: every case red, with the messages naming the consequence (T1 "carry no flow key", T5 no `no_run`, T7 no `tool_call_id`). The strict xfail is the pre-existing async defect. |
| `review_findings_red.txt` | A fresh-context adversarial review of the first build found that run-id reuse could merge two flows (a reused child id; a collision forgotten once the first flow ended), that the memory gate undercounted, and that a handler attached before `unprotect()` kept indexing. These are the tests written for those findings, run red against the first build before the fix. |
| `sabotage.py`, `sabotage_all.txt` | 26 sabotage proofs on the final code. Each removes one piece, runs only its named test (RED, with message), restores the file (sha256 identical before and after) and reruns it (GREEN). S17 (the Python < 3.11 label) ran on pins310, the rest on pins. Four first attempts (S18, S18b, S20, S23) stayed green under sabotage: they exposed overlapping mechanisms and one vacuous benchmark guard. The tests were sharpened until each case went red, and the file records the final attempt. |
| `run_tree_matrix.txt` | `tests/test_run_tree.py` on pins310, pins and latest. |
| `budget_runs.txt` | The D4 gate, three times per environment: stamp p99, handler-callback p99, and memory retained by the run index, counted across ALL files, under three workloads (mixed, root-only abandoned, run-id reuse storm). |
| `wheel_pins.txt` | `tests/test_run_tree.py` and `tests/test_real_frameworks.py` run against the BUILT WHEEL at the pins, from a copy of `tests/` with no `xaidr/` beside it. The import path printed is site-packages. |
| `affected_final.txt` | The affected test files in all four configurations. `test_b9_middleware_full_boundary.py` is run on its own (see the next row). |
| `flake_compare.txt` | Two pre-existing test-harness defects, measured at `0502c99` in a detached worktree. (1) `test_b9_middleware_full_boundary.py` fails 6 of 6 when run after the other affected files with real LangChain installed, and passes alone. The failures are identical at `0502c99`, and CI never runs that combination. (2) `TestRealToolResultSeam` reads its capture without flushing, so it races the telemetry thread. Run alone, it failed 5 of 25 and then 2 of 25 at `0502c99`, against 1 of 25 and 0 of 25 on this branch. Inside the combined affected run it failed 1 of 5 at `0502c99` and 2 of 5 on this branch. The race exists at the base, and these small samples overlap. Its guarded CI class can turn red at random until the test flushes. |
| `guard_proof.txt` | `.github/run_tree_guard.py` in both directions: GREEN on real runs (py312, py310), RED on an all-skipped run (no LangChain). |
| `async_agent_check.py`, `async_create_agent_crash.txt` | An async `create_agent` under `protect()` raises `NotImplementedError` (no `awrap_tool_call`) at pins and at latest, and identically at `0502c99`. It predates run-tree and is pinned as a strict xfail. |
| `e2e/` | The outside-the-process check. `e2e_sensor.py` ran from the built wheel in its own process: two concurrent LangGraph flows, an inbound scan carrying a W3C `traceparent`, and a direct `tool.run()`. It wrote `events.jsonl`. `e2e_brain.mjs` fed that file to the Brain's real `runEventsBatch` (delphi-sentinel `feat/run-tree-reader`, `a148c3a`) with a capturing fake database. Result: 14 events became 14 rows, `run_root_id` matched the sensor on every stamped row, there were 2 distinct roots, `trace_id` was set on both traceparent rows, and no `no_run` row had a root (`e2e_brain_output.txt`). |

**Not verified here:** a live Brain. That needs `migrations/add-run-root-id.sql`
applied on hosted, a Brain deploy whose `/health` commit includes `a148c3a`, and
an operator-run count of `run_root_id` / `trace_id`. Database access from this
machine is blocked on purpose.
