# fix/l1-superlinear — four super-linear L1 rules + the audit gap that passed them

## Summary

Four L1 rules backtracked super-linearly on a shape the ReDoS audit never built:
the rule's own leading phrase followed by a long run of whitespace and nothing
else. That gets the engine into the pattern's ambiguous middle (consecutive
`\s*`/`\s+`/optional-group/`[:\s]+` quantifiers), where one whitespace run is
partitioned many ways while the trailing required token never arrives.

The four rules: `LLM01_persona_expanded`, `LPCI_S6_split_payload`,
`LLM01_fake_authority_marker`, `LLM01_decode_execute_expanded`.

## 1. Failing test first (the audit gap)

Added to `tests/test_redos_pattern_audit.py` (section 7):

- `test_every_rule_bounded_on_its_own_trigger_then_whitespace` — generates the
  seed **per rule, from its own compiled pattern** (walks the parse tree, emits
  the longest letters-and-single-spaces prefix, stops at the mouth of the
  ambiguous middle), appends a whitespace run, asserts a per-pattern ceiling.
  Sweeps **every** rule in `ALL_RULES`, so a rule the maintainer forgets cannot
  dodge it.
- `test_generated_trigger_growth_is_not_superlinear` — the **growth-ratio** gate
  applied on the same generated shape, 4× step, over every rule.

**Second defect in the gate, named.** The pre-existing
`test_growth_is_not_superlinear` stayed green on all four for two independent
reasons: (a) it is parametrized over a hand-maintained `GROWTH_RULES` list none
of the four is on, and (b) it only measures the fixed `battery()` shapes, which
never include this shape. It reported coverage it was not performing. The new
growth test depends on neither a list nor a fixed battery.

### Red, against the pre-fix patterns (committed HEAD), `PYTHONDONTWRITEBYTECODE=1`

Both new gates went red (`2 failed`) and each named all four rules: the
per-pattern ceiling and the growth ratio. The raw failure output is not
reproduced here because it prints each rule's generated seed beside its timing.
To regenerate it, run the two tests above against the pre-fix
`xaidr/rules/all-l1-rules.json`.

(This red *is* the sabotage/restore proof required by RULES: the pre-fix HEAD
carries the old patterns, and the new audit shape reddens against them.)

## 2. The fix — bounded, non-overlapping constructions

The root cause in each is **adjacent whitespace-eating quantifiers** that split
one whitespace run many ways. Each fix collapses them into a single bounded,
non-overlapping class (counting-style bound, the same posture as the repetition
detector that replaced the hanging phrase-repeat regex):

- `fake_authority`: `\s*:?\s*` → `[\s:]{0,8}`
- `LPCI_S6`: `\s*(?:of\s+\d+)?[:\s]+` → `(?:\s+of\s+\d+)?[:\s]{1,8}` (killed the
  unbounded `[:\s]+` and the standalone `\s*` in front of it)
- `persona`: the stacked `(?:a )?(?:AI)?\s*(?:called)?\s*\w+` middle → one bounded
  `[^\n]{0,80}?`
- `decode`: `\s+(?:it)?\s*[:.]?\s*` → `(?:\s+it)?[\s:.]{0,8}`

~~Each `_why_changed` in the rule JSON records the specific defect and bound.~~
**No longer true (2026-10-08):** the rule JSON carries no annotation fields.
They were removed from every rule asset and `tests/test_rule_asset_annotations.py`
now refuses any `_`-prefixed key there. The records are in git history.

### Green, after the fix

```
tests/test_redos_pattern_audit.py  47 passed in 8.69s      # 45 + 2 new
tests/test_agentic_abuse_l1.py tests/test_tool_arg_agentic_categories.py
                                   82 passed in 0.11s
```

## 3. Sweep of all 224 patterns on the new shape

Pre-fix: exactly the four exceeded the 50 ms bar, and no others. Post-fix:
**0 rules over 50 ms**.

## 4. Detection must not regress — rules-only, before vs after

| corpus | before | after |
|---|---|---|
| heldout | 16/50 catch, 6/50 FP | **16/50, 6/50** (identical) |
| asi_battery | (table) | **identical before/after** |
| benign_a2a | 0/60 FP | 0/60 FP |
| benign_toolcall | 0/190 FP | 0/190 FP |
| benign_longform | oversized-only | **identical** |

No recall loss, no new false positive.

## 5. The 0.5 s scan budget does NOT bound a single rule (confirmed, not fixed here)

`xaidr/scanner/l1.py::scan_l1`: `_L1_SCAN_BUDGET_SEC` (0.5 s) is checked at the
**top** of the loop, before each rule; `_L1_RULE_SLOW_SEC` (1.0 s) is checked
**after** the rule returns. Between those two checks the rule's `re.search`/
detector runs to completion — and the file itself states a C-level `re.search`
is uninterruptible in CPython. So the budget bounds *how many rules are entered*,
not the time any one rule spends, and the guards only **record** a slow rule
afterward. This is the guard that looks like protection.

Not fixed on this branch: it is not a one-line change (needs a timeout-capable
engine such as the `regex` module, or process/thread isolation). Reported per the
goal. The real fix is the one applied above — make every pattern linear — which
is what the file's own comment says the budget can never substitute for.
