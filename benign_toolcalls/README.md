# Benign tool-call corpus

190 benign tool calls that look like production traffic, across five agent
personas. It exists to gate the boundary detectors proposed in
`asi_battery/BOUNDARY_GAP.md` **before** any of them goes default-on.

## Why this corpus, and why first

The ASI battery ships with a register-matched benign mirror. That mirror is a
**lower** bound on false positives, not an upper one: it was written one-to-one
against the attacks, so it shares their vocabulary, their tool names, and their
argument shapes. Real agent tool calls do not. A detector measured only against
the mirror is measured against its own author's imagination of benign, which is
the same error that made nano's withdrawn 2.20% meaningless on security prose.

So G1 through G3 in `BOUNDARY_GAP.md` cannot be judged safe against the mirror
alone. This corpus is the production-shaped benign set they have to clear.

## What's here

| File | What it is |
|---|---|
| `corpus.jsonl` | 190 benign tool calls, full argument dicts |
| `../scripts/benign_toolcall_report.py` | regenerates the numbers below |
| `last_run.json` | machine-readable summary of the last local run (git-ignored) |

Each entry records `persona`, `tool`, a full `args` dict with realistic names
and values, and two prose fields, `represents` and `why_benign`, so a reader can
dispute any single entry's benignness.

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

Measured on the shipped sensor, `main` (85a2f98), monitor mode.

**1. Current sensor, the required baseline.** Before any new detector exists:

| persona | n | rules false positives |
|---|---:|---:|
| support | 38 | 0 |
| devops | 40 | 0 |
| data | 38 | 0 |
| research | 36 | 0 |
| finance | 38 | 0 |
| **total** | **190** | **0 (0.0%)** |

The current sensor flags nothing here, which is consistent with the boundary
gap: it barely inspects the tool-call boundary at all. `rules+nano` is identical,
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
