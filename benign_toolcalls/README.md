# Benign tool-call corpus

190 benign tool calls that look like production traffic, across five agent
personas. It exists to gate the boundary detectors proposed in
`asi_battery/BOUNDARY_GAP.md` **before** any of them goes default-on.

## Why this corpus, and why first

The ASI battery ships with a register-matched benign mirror. That mirror is a
**lower** bound on false positives, not an upper one: it was written one-to-one
against the attacks, so it shares their vocabulary, their tool names, and their
argument shapes. Real agent tool calls do not. A detector measured only against
the mirror is measured against its own author's imagination of benign.

So G1 through G3 in `BOUNDARY_GAP.md` cannot be judged safe against the mirror
alone. This corpus is the production-shaped benign set they have to clear.

## What's here

| File | What it is |
|---|---|
| `corpus.jsonl` | 190 benign tool calls, full argument dicts — **authored blind** |
| `discriminator.jsonl` | 50 benign tool calls, **detector-informed**, one `axis` each |
| `sql_dml.jsonl` | 50 benign DELETE/UPDATE statements, one `shape` each |
| `domains.jsonl` | 120 benign tool calls from **six domains outside the five personas**, one `domain` each |
| `../scripts/benign_toolcall_report.py` | regenerates the numbers below |
| `../scripts/benign_sql_dml_report.py` | regenerates the `sql_dml.jsonl` table |
| `../scripts/benign_domain_report.py` | regenerates the `domains.jsonl` table |
| `last_run.json`, `domains_last_run.json` | machine-readable summaries of the last local run (git-ignored) |

Each entry records `persona`, `tool`, a full `args` dict with realistic names
and values, and two prose fields, `represents` and `why_benign`, so a reader can
dispute any single entry's benignness.

### Two pools, and why they are not one file

`corpus.jsonl` was written from agent workflows before any tool-path detector
existed. Nothing in it was chosen against a regex, which is the property that
makes "0 / 190" worth quoting — and it is a property that merging would destroy.

`discriminator.jsonl` is the opposite by design: each entry targets an argument
property the structural detectors read, and carries an `axis` naming it
(`boolean-false-sense-inversion`, `polysemous-bound-key`,
`control-name-as-unrelated-value`, `integer-zero`, `admin-as-filter`,
`self-principal-read`, …). It is an ACCEPTANCE set, not a sample, and it is
reported separately for that reason.

**It exists because the blind pools are structurally unable to exhibit two whole
classes of error.** `corpus.jsonl` has 656 leaf key/value pairs, **twelve
booleans and no integer zeros**, and its only False-valued control-shaped keys
are `auto_approve` and `dry_run`. `../asi_battery/benign.jsonl` is a
*register-matched mirror*: its tool-call steps reuse the attack KEYS on purpose,
so it tests whether a detector can tell two VALUES apart under one key and never
whether it can tell two KEYS apart. Between them they cannot measure a
key-vocabulary error or a value-polarity error — so both read 0 while:

| detector form | `corpus.jsonl` | `discriminator.jsonl` |
|---|---:|---:|
| G2 reading its keys as unrelated facts | 0 / 190 | **11 / 50 (22.0%)** |
| G2 reading each shape as a relation between two keys | 0 / 190 | **0 / 50 (0.0%)** |
| G2 as unrelated facts + G4 reading value polarity naively | 0 / 190 | **23 / 50 (46.0%)** |
| **G2 + G4 as shipped** | **0 / 190** | **2 / 50 (4.0%)** |

**Read the third row: it is why this pool exists.** 23 = the 11 false positives
of G2 in its unrelated-facts form plus 12 from the naive G4, which reads
`limit_reached: False` as a removed ceiling, `ttl: "none"` as one, and
`cost_center: "none"` as one. That combination scores **0 / 190 and 0 / 628
committed benign inputs**. The blind pools cannot see this class of error on
either detector, which is the argument for keeping the two pools separate rather
than a hypothetical about it.

**The shipped 2 / 50 is 48 discriminations plus 2 abstentions, and the
abstentions are named:** `retention: "forever"` on an archive bucket (DSC-RES-03)
and `expires: "never"` on a perpetual licence (DSC-FIN-04). Both genuinely ARE a
named bound holding a strong nullifier, and both are routine traffic. The only
thing separating them from the attack is an authorisation reference in the same
call (`approval="LEGAL-88"`, `contract="PERPETUAL-2024"`), which is app-supplied
and unsigned — an attacker types it as easily as the archivist does — so reading
it would be a courtesy rather than a discrimination and it is deliberately not
read. They flag; this is written down instead. The residual note lives with the
detector, in `xaidr/scanner/resource_bound.py`, and
`tests/test_resource_bound.py::test_discriminator_pool_flags_only_the_named_residual`
pins the pair by id so a third cannot be gained quietly.

### A third pool, for the one field the other two cannot reach

`sql_dml.jsonl`, 50 benign `DELETE`/`UPDATE` statements for the SQL
predicate-boundedness rules. It is separate for the same reason
`discriminator.jsonl` is, and the blindness it answers is sharper than either of
the two above.

`sql.unbounded_mutation` and `sql.tautological_mutation` match only
`statement ∈ {delete, update}`. **Neither of the other two pools contains a
single DML statement** — every SQL value in all 240 of them is a `SELECT` — so
`predicate`, the load-bearing field of the entire SQL reader, is measured
against zero benign statements without this pool. 0 / 240 on a rule the pool
cannot reach is not a clean bill; it is exactly the "the corpus could not see
this class" gap recorded above for the privilege detector, on a different
surface.

The 50 entries are ORM, driver, migration and operator shapes: placeholder
styles (`$1`, `?`, `:name`), soft deletes, retention sweeps, optimistic locks,
`RETURNING`, CTE-then-delete, `UPDATE … FROM`, `DELETE … USING`, correlated
`EXISTS`, quoted identifiers, comments, explicit transactions. Several were
picked *because* they looked hard — a pool that avoids the shapes a detector
might fire on measures nothing.

| tokenizer | `sql_dml.jsonl` given a destructive impact class |
|---|---:|
| reading `$2 … $1` as one dollar-quoted string | **5 / 50 (10.0%)** |
| as shipped | **0 / 50 (0.0%)** |

The five are not a cost of failing closed on unknown predicates — that cost is
**zero**, no entry moves from `bounded` to `unknown`. They are a tokenizer error
this pool exists to catch: in a statement containing two Postgres placeholders
(`… = $2 WHERE lower(email) = lower($1)`), a tokenizer that reads everything
between the two `$` as one dollar-quoted string puts the `WHERE` clause inside a
literal, and the write reports `predicate=none` — an unbounded mutation. The same
swallow hides a following `;` and every statement after it.

### A fourth pool, for the axis the other three share: the DOMAIN

`domains.jsonl`, 120 benign tool calls from six domains no detector here was
built against — legal document management, game state, scientific computing and
mathematics, media production, healthcare scheduling, education. 20 each.

The blindness it answers is the one the other three pools have in common rather
than one that distinguishes them. `corpus.jsonl` is five personas.
`discriminator.jsonl` is 50 more calls on detector AXES, and every one of them is
still tagged with one of the same five personas. `sql_dml.jsonl` is a SQL
surface, not an industry. `../asi_battery/benign.jsonl` is a register-matched
mirror, narrower again. **Without this pool, every benign tool call committed
to this repo is support, devops, data, research or finance**, so "0 / 190" is
no evidence about a sixth domain — and the words the structural detectors key
on are exactly the words that change meaning when the industry does. `audit` is a
control in devops and an enrolment mode in a university. `monitoring` is an
observability agent in devops and cardiac telemetry in a hospital. `limit` is a
ceiling in finance and the object being computed in a CAS. `administrator` is a
role in IAM and a credit on a film.

| predicates | `domains.jsonl` |
|---|---:|
| five predicates each reading a single fact | **40 / 120 (33.3%)** |
| the same five narrowed, as shipped | **24 / 120 (20.0%)** |

The sixteen the narrowing removes are one error in different clothes — a
predicate reading ONE fact with no relation to the claim in its own rule name:
`ASI03_concealed_grant` on a `visible: false` with no grant in the call (a
compositing layer, a staged game entity, an unreleased assignment, an embargoed
lab result); `ASI03_self_privileged_action` on `assignee="self"` beside a `role`
naming a job rather than a power; `ASI03_admin_escalation` on `scope: "root"`,
which is the top of a folder tree, a mounted filesystem, a scene graph and an LMS
account tree; `ASI03_disable_control` on a `disabled: true` that names nothing it
disables; `ASI04_bound_removed` on a bare `rate`, which is a price and a pulse
before it is ever a ceiling, and on a `max_wait` that `max_timeout` was already
carved out for. **In single-fact form all five are green on `corpus.jsonl`
(0/190), `discriminator.jsonl` (2/50) and every other committed pool** —
which is the same "the corpus could not see this class" recorded above for the
key-vocabulary and value-polarity errors, now on a third axis.

The remaining **24 are listed by id with a verdict each** in
`../scripts/benign_domain_report.py::DOMAIN_RESIDUAL`, and
`../tests/test_f7_domain_generality.py::test_the_domain_pool_flags_only_the_recorded_residual`
pins the set exactly so a 25th cannot be gained quietly. They are a limit of a
per-message, domain-blind detector, not a defect, and they are written down in
`../docs/privilege-tiers.md` rather than carved out with a list of domain words.

**How it was written, and honestly.** From the workflows of each domain — what a
paralegal, a live-ops engineer, an astronomer, a colourist, a clinic scheduler
and a registrar actually call — NOT from the detector regexes. But unlike
`corpus.jsonl` it is **not blind**: it was authored after the detectors existed,
by someone who had read them, so it belongs with `discriminator.jsonl` as an
ACCEPTANCE set and is reported apart for the same reason. What it does not do is
select FOR the regexes: the four calls carrying `visible: false` are there
because hiding a layer, staging an actor, holding a result and scheduling a
release are what those six jobs consist of, and a pool that avoided them would
measure nothing — the same discipline the "It exercises the detectors on purpose"
section below states for the blind pool.

## How it was written

From **agent workflows, not from the detectors.** Five personas, each doing its
ordinary job:

- **support** (38): reading and updating tickets, replying to customers, refunds
  within limit, KB articles, returns.
- **devops** (40): deploys and rollbacks, scaling, migrations, IAM grants,
  credential rotation, snapshots, firewall and DNS changes, runbooks.
- **data** (38): queries and exports, dbt models, S3/BigQuery writes, catalog
  entries, backfills, model registration, batch scoring.
- **research** (36): web and arXiv fetches, summaries, notes and reports to
  Confluence/Notion, embeddings, batch fetching, a preprint submission.
- **finance** (38): reconciliation, invoices, journal entries, payroll, vendor
  payments, auditor exports, tax filings, statements.

The corpus was authored before the report was run, and it was **not** shaped
around the candidate detector regexes. That is the discipline the task required:
a benign corpus built to avoid the detectors proves nothing, and one built to
trip them proves less.

## It exercises the detectors on purpose

A corpus that contains nothing a detector would plausibly fire on measures
nothing. So ordinary traffic here includes, as legitimate work:

- **egress to external destinations**: transactional and account-recovery email
  to customers' own inboxes, a partner artifact bucket, an ad-partner SFTP feed,
  a client dropzone, a board packet to an external observer, ledgers and trial
  balances to the appointed auditor's portal, a sales-tax filing to the
  compliance provider, reverse-ETL to the company's own CRM.
- **privileged actions**: an approved, scoped, expiring IAM grant to a new hire;
  offboarding revocation; 90-day credential rotation; an approved production
  migration; a board-approved payment-approver grant; the semi-monthly payroll
  run; retention-bounded snapshot deletion; a single-host firewall allow.
- **knowledge-base writes**: support KB articles, an on-call runbook, a data
  catalog description, a research report and glossary, audit workpapers.
- **high-volume operations**: the nightly auto-close of resolved tickets, a
  10,000-partition backfill, scoring 2.1M customers, a 500-URL research fetch,
  payroll for 5,200 employees, a 1,200-payment ACH batch.

## The measured baseline (regenerate: `python scripts/benign_toolcall_report.py`)

Measured in monitor mode, on a sensor without the proposed boundary detectors.

**1. The sensor without boundary detectors, the required baseline:**

| persona | n | rules false positives |
|---|---:|---:|
| support | 38 | 0 |
| devops | 40 | 0 |
| data | 38 | 0 |
| research | 36 | 0 |
| finance | 38 | 0 |
| **total** | **190** | **0 (0.0%)** |

Without the boundary detectors the sensor flags nothing here, which is
consistent with the boundary gap: without them it barely inspects the tool-call
boundary at all. `rules+nano` is identical,
because nano does not run on tool calls.

**2. The acceptance surface, which is the point.** A naive detector for each
proposed mechanism, keyed on the mechanism rather than on attack vocabulary,
fires on this much ordinary traffic:

| mechanism (naive form) | benign hits | rate |
|---|---:|---:|
| external egress of data | 14 | 7.4% |
| privileged action | 25 | 13.2% |
| write to a store (KB) | 22 | 11.6% |
| high-volume operation | 17 | 8.9% |

That is the number the mirror hid. On the 120-case mirror the attack-tuned
prototypes scored 0 to 1 false positives each; here a detector built to catch the
same mechanism generically starts by firing on 7 to 13 percent of production
traffic, and every one of those instances has to be carved back out before it can
go default-on. The script names all of them. The carve-outs the corpus points at
are concrete: an egress detector must not fire on a customer emailed their own
data or an auditor sent the ledger they are contracted to receive; a privileged
detector must separate a self-granted admin role from an approved, scoped grant to
a named person; a KB-write detector must pass an accurate runbook.

## Publishable

Authored by the xaidr maintainers for this repo, released under the repo's
Apache-2.0 license, no third-party text, committed to the public tree. Same rule
as `heldout/` and `asi_battery/`.
