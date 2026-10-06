# Consumers of the value-origin wire vocabulary: what each needs for a tenth value

**Inventory only.** Nothing outside this repo was changed. The census was
read-only (2026-10-04, at xaidr `efe2ad7`). The tenth value is `input_truncated`
(owner, after A2 M6): its verdict is `not_evaluated`, its row state
`not_recorded`, and an untrusted finding outranks it.

**Headline.** One consumer outside xaidr encodes the vocabulary today: the
Brain, on delphi-sentinel branch `feat/value-origin-brain` (`a603239`) **and on
`origin/main` (`01450c7`, #137), where those four files are identical** *[corrected by the
pre-M8 review: the census said origin/main could not be read; it can, and the Brain code is merged]*. It
hard-codes NINE values and would store `input_truncated` as **NULL**: silent
data loss in the state that exists to make truncation visible. blank-canvas has
no value-origin code yet. The paid repo (`delphi-python-sdk`) has no vendored
copy and no pin machinery yet. The database column has no CHECK, enum or
DEFAULT, so **no migration is needed for the value**, only a corrected column
comment.

| # | Repo / branch, file:line | Encodes | Today, given `input_truncated` | Needed |
|---|---|---|---|---|
| 1 | delphi-sentinel `feat/value-origin-brain`: `src/value-origin.ts:22-37` | closed list `VALUE_ORIGINS` (9); `isValueOrigin` gives NULL for anything else | `readValueOrigin` (`events-batch.ts:134-138`) returns null. The row is written with `value_origin` NULL (`:388`), counted in `valueOriginRejected` (`:270-278`), one `[VALUE_ORIGIN]` warning per batch (`:707-714`) | add `'input_truncated'` |
| 2 | same: `value-origin.ts:42-58` `verdictOf` | exhaustive switch over 9 | unreachable today | add a case returning `not_evaluated` (likely a tsc error if the list grows without it; tsconfig not checked) |
| 3 | same: `value-origin.ts:84-115` `valueOriginRow` | §3.4 row table: 9 + NULL + unrecognised fallback | a stored value renders `not_recorded`, "unrecognised value `input_truncated`" | add the row, text from xaidr `_evaluate.py` `_ROWS["input_truncated"]` |
| 4 | same: `src/value-origin.test.mjs:17-20, 42-50, 55-69` | hand-written list of 9; transcribed rows; `ROWS.length === NINE.length+1` | green; goes red as soon as #1 changes (intended) | add the value; per its own note (#136), assert against `row_text.json` instead of transcribing |
| 5 | same: `src/events-batch.test.mjs:737-740` | `WIRE_VALUES` (9) | not exercised | add the value |
| 6 | same: `migrations/add-value-origin.sql:13-27, 53-54` | `COMMENT ON` says "one of nine values"; nullable `text`, no CHECK, no DEFAULT | the DB accepts any text; the comment is wrong | re-issue `comment on column` (a **delphi-sentinel/migrations** change, not blank-canvas) |
| 7 | same: `docs/sql/verify-value-origin.sql:103-105` | query 4: `NOT IN` the nine "MUST RETURN ZERO ROWS" | would flag every legitimate `input_truncated` row as junk | add the value |
| 8 | same: `docs/value-origin-architecture.md:421, 481, 514-523` (older copies on 4 other branches) | spec §2 / §3.2 / §3.4 tables (9) | documentation | add the row |
| 9 | delphi-sentinel `feat/corpus-poisoned-reads`: `bench/action-path-corpus/reference_ledger.py:48-49` | the five resolved wire values only | n/a | none, unless a case's principal input exceeds 65,536 chars |
| 10 | **paid = delphi-python-sdk** (main + 3 worktrees): `xaidr/authz/policy.py:48` `EVALUATOR_GENERATION = 1`; `scripts/ci_guards.py:50-52` on `ci/test-workflow` mentions a future pin | no vendored `xaidr/value_origin`, no `vendor_value_origin.py`, no pin json, no P1-P4 tests (designed in sentinel `docs/value-origin-architecture.md:581-621`) | nothing reads it | on re-vendor the tree arrives byte-identical; P4 bumps the generation only if `expected.jsonl`'s sha moved (it has, several times in A2); any paid code consuming `wire` (the M9 emitter) must handle ten |
| 11 | blank-canvas (main + 18 worktrees): `src/lib/waterfallCore.ts:166-172` `StageState` | the six `RowState` spellings match; no `value_origin` in types, no intent stage, no migration | not selected, not rendered | build the intent stage (V-28) with a ten-value table checked against `row_text.json` |
| 12 | `~/delphi` monorepo (not in the CLAUDE.md repo list), `feat/layers-spec`: `docs/port/layers-spec.md:909-912, 918-923, 991` | port spec citing nine values | documentation | update before the port is built |
| — | xaidr itself | `verdict_of`'s docstring said "nine" | — | **fixed in this commit** (docstring only; a paid pin byte change) **[Incomplete: the same docstring still said "outside the nine" until 2026-10-05; now "twelve".]** |

**Effective rule for `ai_guard_logs.value_origin`.** Its only definition is the
sentinel migration (on `origin/main` too, so it is merged, though whether it is APPLIED to the live
database is unverified).
- CHECK: none, deliberately (`add-value-origin.sql:37-43`).
- Trigger: `trg_validate_feedback_status` checks only `feedback_status`.
- NOT NULL, DEFAULT, enum: none.
- RLS: row-scoped `WITH CHECK` (blank-canvas `20260920000000_fix_cross_tenant_write_rls.sql:193-197, 391-396`), silent on this column.
- **Intersection: any text or NULL.** The only guard is the Brain's
  `readValueOrigin`.
- Side effect: the feedback UPDATE policy may let a dashboard user rewrite
  `value_origin` on their own rows. That is a second write path besides the
  Brain. Unverified.

**Not read.**
- ~~delphi-sentinel `origin/main` (`01450c7`, ahead of the checkout).~~ *[It
  was readable: the pre-M8 review diffed it against `feat/value-origin-brain`, and
  the four Brain files are identical. The Brain code is on main.]*
- About 60 sentinel branches without a worktree; 14 blank-canvas branches
  (including `feat/xaidr-brain-port`); delphi-python-sdk `release/0.6.0`,
  `feat/parent-scan-id`, `fix/*`.
- Uncommitted worktree changes.
- delphi-mcp-server, agent-sensor, delphi-l3-service and delphi-rules: main
  checkouts only, no hits (absence in those trees, not proof of no use).

**Unverified live state.** Database access is blocked on purpose. Run these:

```sql
select column_name,data_type,is_nullable,column_default from information_schema.columns where table_schema='public' and table_name='ai_guard_logs' and column_name='value_origin';
select conname,pg_get_constraintdef(oid) from pg_constraint where conrelid='public.ai_guard_logs'::regclass and pg_get_constraintdef(oid) ilike '%value_origin%';
select tgname,pg_get_triggerdef(oid) from pg_trigger where tgrelid='public.ai_guard_logs'::regclass and not tgisinternal;
select coalesce(value_origin,'(not reported)'),scan_mode,count(*) from ai_guard_logs where created_at>now()-interval '7 days' group by 1,2 order by 3 desc;
```

Which Brain build is live decides whether today's behaviour is "stored as NULL"
or "key ignored": `curl -s https://xaidr.delphisecurity.ai/health`, then compare
`commit` with `a603239` and `01450c7`.

**Order that avoids silent loss.**
1. The Brain (#1–#5, #7) accepts the tenth value.
2. The column comment is corrected (#6).
3. Only then may xaidr M9 emit `valueOrigin`.

M9 is held at STOP 4 regardless.

## 2026-10-04: two more wire values

`argument_bound` and `result_truncated` were added (RULING 1+2). Every consumer above that lists the vocabulary, such as the Brain's nine-value list, is now short by more than one value; an unknown value takes the `not_recorded` row there. This is an inventory only: nothing outside this repo was changed.

`result_unread` was added on 2026-10-05 (Q18 under the bounds ruling), making thirteen values. The same inventory applies: nothing outside this repo was changed.

`extraction_incomplete` was added on 2026-10-06 (the atom pass's work budget), making fourteen values. The same inventory applies: nothing outside this repo was changed.

## M9 (2026-10-06): the full final list the consumer must accept

The sensor emits `valueOrigin` at the top level of `data` on every tool-call event (all six exits; never null), mapped to `gen_ai.security.value_origin`, at schema **0.3.0**. **What the consumer must accept: all fourteen values below.** Row state and text are the normative §3.4 rows (`tests/value_origin_conformance/row_text.json` is the machine-readable copy).

| wire value | verdict | row state | emitted under the default `v1`? | blocks under ENFORCE? | row text (tool_call) |
|---|---|---|---|---|---|
| `principal` | authorized | ran_clean | yes | no | Intent: destination traces to the principal's own input (a declared principal span). |
| `principal_undeclared_span` | authorized | ran_clean | yes | no | Intent: destination traces to the principal's input — assuming the whole input was the principal's own; no span structure was declared, so quoted content would read the same. |
| `trusted_source` | authorized | ran_clean | yes | no | Intent: destination traces to a designated trusted source. |
| `untrusted_source` | unauthorized | ran_evidence | yes | yes: `ORIGIN_UNTRUSTED_DESTINATION` + `intent.value_origin_untrusted` | Intent: destination traces to an untrusted source. |
| `unresolved` | unresolved | ran_evidence | yes | no | Intent: destination origin unresolved — it traces to no recorded source. |
| `no_destination` | not_evaluated | not_applicable | yes | no | Intent: not applicable — this call carries no destination-shaped value. |
| `no_flow` | not_evaluated | not_recorded | yes | no | Intent: not evaluated — no flow context was visible to this call (none was started, or it did not reach this thread). |
| `ledger_absent` | not_evaluated | not_recorded | yes | no | Intent: not evaluated — a flow was active but its provenance ledger was never bound; the sensor's flow entry is not wired. |
| `ledger_saturated` | not_evaluated | not_recorded | yes | no | Intent: not evaluated — this flow's ledger was full; an unmatched destination cannot be called novel. |
| `input_truncated` | not_evaluated | not_recorded | **no (withheld)** | no | Intent: not evaluated — this destination traces to no recorded source; the principal's input was longer than value origin examines whole (64 KiB), and the part past that point was scanned only for destination addresses. |
| `argument_bound` | unresolved | ran_evidence | **no (withheld)** | no | Intent: destination not fully examined — this call's arguments exceed what value origin examines whole (a value over 4,000 characters, more than 64 values, or nesting deeper than 6); past that point they were scanned only for destination addresses. |
| `result_truncated` | not_evaluated | not_recorded | **no (withheld)** | no | Intent: not evaluated — this destination traces to no recorded source; a tool result in this flow exceeded what value origin examines whole (a value over 65,536 characters, more than 64 values, or nesting deeper than 6), and the part past that point was scanned only for destination addresses. |
| `result_unread` | not_evaluated | not_recorded | **no (withheld)** | yes: `ORIGIN_UNEXAMINABLE_SOURCE` + `intent.value_origin_untrusted` | Intent: not evaluated — a tool result in this flow was an unread network response (httpx, requests, urllib3 or aiohttp), which value origin does not read so as not to consume it; a destination in it cannot be traced. |
| `extraction_incomplete` | not_evaluated | not_recorded | **no (withheld)** | no | Intent: not evaluated — value origin's scan for destination addresses in a long value reached its work budget; the rest was not scanned, so a destination there may be missed. |

**The gate** (`Sensor(value_origin_wire=...)`, my choice under the owner's "do not emit a value no consumer accepts"):
- `"v1"` (default) emits the nine the Brain's code on delphi-sentinel origin/main (01450c7) accepts.
- `"v2"` emits all fourteen.
- `"off"` emits nothing.

A withheld value leaves the key absent. That is indistinguishable on the wire from "not reported", by design, until the consumer is updated. It is named in a once-per-value warning, and it applies to EVERY reporter (SIEM and file users included).

**Deployed vs main** (milestone review, 2026-10-06): the deployed Brain, `8c01911` per `/health`, predates the value-origin code and ignores the field entirely. origin/main (#137) accepts nine. Whether `add-value-origin.sql` is applied to the live database is unverifiable from here (#84).

**For the consumer to accept all fourteen, change** inventory rows #1–#5 and #7 above for the five new values (`input_truncated`, `argument_bound`, `result_truncated`, `result_unread`, `extraction_incomplete`), plus the column comment (#6) and the spec tables (#8). **Switch the sensor to `v2` only after a DEPLOYED Brain accepts all fourteen.**

**Known gap (host-only):** `sensor.scan(text, direction="tool_call")`, which bypasses `scan_tool_call`, emits a tool-call event without `valueOrigin`. No caller inside xaidr does this.
