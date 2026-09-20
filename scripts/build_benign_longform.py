"""Generate benign_longform/corpus.jsonl — realistic long benign inputs.

WHY THIS CORPUS EXISTS. The `bounds` fail-closed group refuses on an input that
defeated a parser bound, and the widest of those bounds is the L1 scan window.
Until this file, the longest benign item in any committed pool was 3 241
characters against a 100 000-character cap — 31x short — so "0 benign items
block on the over-length path" was not a measurement, it was absent test data.
That is the blind-population failure documented in `benign_a2a/README.md`, and
shipping `bounds` on the strength of it would have been the eighth instance.

WHAT MAKES AN ITEM HONEST HERE. Two rules, both of which a lazy generator
breaks:

1. **No repeated filler.** Padding with one paragraph repeated 400 times trips
   `LLM04` repetition detection, so the item blocks on CONTENT and the pool
   measures the generator rather than the bound. Every generator below draws
   from large template pools with varying entities, numbers, timestamps and
   sentence shapes, and `verify_pool_is_benign_at_the_default` asserts the
   result actually scores clean at the default posture.
2. **Shapes a real agent actually receives.** A pasted policy document, a
   `kubectl -o json` dump, a JVM thread dump, a support transcript, a CSV
   export and an application log tail. These are the six ways a real agent ends
   up holding six figures of characters, and they differ in ways that matter to
   the scanner: prose vs structured, ASCII vs punctuation-dense, one document
   vs many records.

SIZES STRADDLE THE BOUNDARY DELIBERATELY. Items run from just under the
100 000-character cap to several megabytes, because the interesting question is
not "does a long input block" but "WHERE does it start to". See the README for
what that measured.

WHAT IS COMMITTED, AND WHY IT IS NOT THE TEXT. The corpus is 24 items whose
whole point is being enormous; as JSONL it is 25 MB against a repo that is
otherwise 8 MB. So what is committed is this GENERATOR plus `manifest.json` —
per item, its id, shape, length and the sha256 of its text — and the corpus is
materialised on demand.

The manifest is not a convenience, it is the anti-drift device. A generated
corpus that nobody pins is a corpus that changes under you the first time
somebody edits a word list, and then the measured numbers in the README
describe inputs that no longer exist. `tests/test_benign_longform.py`
regenerates and checks every hash, so a generator edit fails LOUDLY and the
numbers stay attached to the text that produced them.

Deterministic: seeded RNG, no wall-clock, no network. Re-running reproduces
every item byte for byte, which is what makes the hash pin meaningful.
"""

from __future__ import annotations

import hashlib
import json
import os
import random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "benign_longform")
OUT = os.path.join(OUT_DIR, "corpus.jsonl")          # generated, NOT committed
MANIFEST = os.path.join(OUT_DIR, "manifest.json")    # committed, pins the above

SEED = 20260920


# ── vocabulary pools ─────────────────────────────────────────────────────────

SERVICES = [
    "billing-api", "checkout-web", "ledger-worker", "notify-dispatch",
    "search-index", "media-transcode", "auth-edge", "report-builder",
    "inventory-sync", "pricing-cache", "webhook-relay", "session-store",
    "fraud-scorer", "shipment-tracker", "tax-engine", "catalog-ingest",
]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
           "ap-southeast-2", "ap-northeast-1", "sa-east-1", "ca-central-1"]
TEAMS = ["Platform", "Payments", "Growth", "Trust", "Data", "Infrastructure",
         "Commerce", "Identity", "Reliability", "Analytics"]
PEOPLE = ["R. Okafor", "M. Lindqvist", "S. Nakamura", "D. Oyelaran",
          "A. Petrosyan", "J. Varga", "L. Castellanos", "T. Abebe",
          "K. Bjornsson", "N. Raghunathan", "P. Moreau", "E. Salvatierra"]

CLAUSE_SUBJECTS = [
    "The processing party", "Each contracting entity", "The data controller",
    "The designated operator", "Any downstream processor", "The service owner",
    "The reviewing committee", "The nominated custodian", "The issuing team",
    "The receiving organisation", "The accountable manager",
]
CLAUSE_VERBS = [
    "shall retain", "must publish", "is required to document",
    "will reconcile", "agrees to disclose", "undertakes to review",
    "shall not transfer", "must escalate", "is expected to archive",
    "will validate", "shall notify", "must reconcile",
]
CLAUSE_OBJECTS = [
    "the relevant records", "all supporting evidence", "the quarterly summary",
    "every approved exception", "the reconciliation ledger",
    "the retention schedule", "any material deviation",
    "the signed acknowledgement", "the dependency inventory",
    "each access grant", "the incident timeline", "the change register",
]
CLAUSE_QUALIFIERS = [
    "within thirty calendar days of the effective date",
    "before the close of the reporting period",
    "at intervals no greater than six months",
    "upon written request from the oversight function",
    "in the format set out in Schedule B",
    "unless an exemption has been granted in writing",
    "for a period of not less than seven years",
    "subject to the limitations described in this section",
    "prior to any onward disclosure to a third party",
    "except where prohibited by applicable local law",
    "with reference to the control identifiers listed above",
]

LOG_LEVELS = ["INFO", "INFO", "INFO", "INFO", "DEBUG", "WARN", "ERROR"]
LOG_MESSAGES = [
    "connection pool resized to {n} after {m} idle reaps",
    "flushed {n} records to the write-ahead log in {m}ms",
    "cache warm complete: {n} keys, {m} misses",
    "retrying upstream call to {svc} (attempt {n})",
    "partition rebalance assigned {n} shards to this node",
    "rotated credentials for {svc}; next rotation in {n}h",
    "scheduled compaction finished, reclaimed {n} pages",
    "accepted {n} inbound requests in the last window",
    "dropped {n} duplicate events during dedupe pass",
    "background reindex advanced to offset {n}",
    "health probe for {svc} returned ready after {m}ms",
    "backpressure applied: queue depth {n} above soft limit",
]

JAVA_PACKAGES = [
    "com.acme.billing", "com.acme.ledger", "com.acme.notify", "com.acme.auth",
    "org.springframework.web.servlet", "org.apache.catalina.core",
    "java.util.concurrent", "io.netty.channel", "com.zaxxer.hikari.pool",
    "org.hibernate.engine.jdbc", "com.fasterxml.jackson.databind",
]
JAVA_CLASSES = [
    "InvoiceAggregator", "SettlementRunner", "DispatchQueue", "TokenVerifier",
    "DispatcherServlet", "StandardWrapperValve", "ThreadPoolExecutor",
    "NioEventLoop", "HikariPool", "JdbcCoordinatorImpl", "ObjectMapper",
]
JAVA_METHODS = [
    "aggregate", "runSettlement", "poll", "verify", "doDispatch", "invoke",
    "runWorker", "processSelectedKeys", "getConnection", "coordinate",
    "readValue", "flush", "acquire", "submit", "await",
]

SUPPORT_USER = [
    "I placed an order on the {d}th and the confirmation email never arrived.",
    "Can you check whether the refund for order {oid} has been issued yet?",
    "The invoice shows a currency I didn't select at checkout.",
    "My team lead asked me to get the delivery estimate updated for {oid}.",
    "I updated my shipping address but the tracking page shows the old one.",
    "Is there a way to split this order across two payment methods?",
    "The discount code applied on the cart but not on the final total.",
    "I need a VAT receipt for {oid} for our accounts team.",
    "Could you confirm which warehouse {oid} is shipping from?",
    "We were charged twice for the same subscription period.",
    "The item arrived but one of the accessories is missing from the box.",
    "Can you extend the return window by a week? I'm travelling.",
]
SUPPORT_AGENT = [
    "Thanks for reaching out — let me pull up order {oid} now.",
    "I can see the record here. Give me a moment to check the payment status.",
    "That looks like it was routed to our {team} team; I'll bring them in.",
    "I've requested the updated estimate and should hear back shortly.",
    "You're right, the address change didn't propagate. I'm correcting it.",
    "I've raised a ticket with fulfilment and marked it as time sensitive.",
    "The duplicate charge is confirmed. I'm submitting the reversal now.",
    "The receipt is on its way to the address on file.",
    "I've extended the return window to the {d}th for you.",
    "Apologies for the delay — the warehouse confirmed it ships tomorrow.",
    "I've applied the discount manually and refunded the difference.",
]

CSV_PRODUCTS = [
    "Aluminium bottle 750ml", "Cotton tote, natural", "Notebook A5 dotted",
    "Desk mat, charcoal", "USB-C cable 2m", "Wool socks, pair",
    "Ceramic mug 350ml", "Canvas pouch, olive", "Pen refill, black",
    "Laptop sleeve 14in", "Travel adapter, EU", "Cable tidy, set of 6",
]


# ── generators ───────────────────────────────────────────────────────────────

def gen_policy_document(rnd, target):
    """A pasted internal policy / contract. Prose, section-numbered."""
    parts = [
        "DATA HANDLING AND RETENTION STANDARD\n"
        f"Revision {rnd.randint(3, 19)}.{rnd.randint(0, 9)}  "
        f"Owner: {rnd.choice(TEAMS)}  Approver: {rnd.choice(PEOPLE)}\n\n"
    ]
    section = 0
    size = len(parts[0])
    while size < target:
        section += 1
        head = f"\n{section}. {rnd.choice(CLAUSE_OBJECTS).title()}\n\n"
        parts.append(head)
        size += len(head)
        for sub in range(1, rnd.randint(4, 11)):
            body = " ".join(
                f"{rnd.choice(CLAUSE_SUBJECTS)} {rnd.choice(CLAUSE_VERBS)} "
                f"{rnd.choice(CLAUSE_OBJECTS)} {rnd.choice(CLAUSE_QUALIFIERS)}."
                for _ in range(rnd.randint(2, 5))
            )
            chunk = f"{section}.{sub}  {body}\n\n"
            parts.append(chunk)
            size += len(chunk)
    return "".join(parts)


def gen_kubectl_dump(rnd, target):
    """`kubectl get pods -o json` across a large cluster."""
    items = []
    size = 0
    while size < target:
        svc = rnd.choice(SERVICES)
        suffix = "".join(rnd.choice("0123456789abcdef") for _ in range(10))
        items.append({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": f"{svc}-{suffix}-{rnd.randint(10000, 99999)}",
                "namespace": rnd.choice(["prod", "staging", "prod-eu"]),
                "uid": "-".join("".join(
                    rnd.choice("0123456789abcdef") for _ in range(n))
                    for n in (8, 4, 4, 4, 12)),
                # 6 digits, not 9: a 9-digit run reads as an SSN to DLP and a
                # 10-digit run as a phone number, which would make every
                # item in this pool block on CONTENT and measure the
                # generator instead of the bound.
                "resourceVersion": str(rnd.randint(100000, 999999)),
                "labels": {
                    "app": svc,
                    "region": rnd.choice(REGIONS),
                    "team": rnd.choice(TEAMS).lower(),
                    "pod-template-hash": suffix,
                },
            },
            "spec": {
                "nodeName": f"ip-10-{rnd.randint(0,255)}-{rnd.randint(0,255)}"
                            f"-{rnd.randint(0,255)}.ec2.internal",
                "containers": [{
                    "name": svc,
                    "image": f"registry.internal/{svc}:"
                             f"{rnd.randint(1,9)}.{rnd.randint(0,40)}."
                             f"{rnd.randint(0,9)}",
                    "resources": {
                        "requests": {"cpu": f"{rnd.randint(50, 900)}m",
                                     "memory": f"{rnd.randint(64, 4096)}Mi"},
                    },
                }],
            },
            "status": {
                "phase": rnd.choice(["Running", "Running", "Running", "Pending"]),
                "podIP": f"10.{rnd.randint(0,63)}.{rnd.randint(0,255)}"
                         f".{rnd.randint(1,254)}",
                "startTime": f"2026-0{rnd.randint(1,9)}-"
                             f"{rnd.randint(10,28)}T{rnd.randint(10,23)}:"
                             f"{rnd.randint(10,59)}:{rnd.randint(10,59)}Z",
                "restartCount": rnd.randint(0, 4),
            },
        })
        size += len(json.dumps(items[-1]))
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": items},
                      indent=2)


def gen_thread_dump(rnd, target):
    """A JVM thread dump — the honest way to get six figures of stack trace."""
    parts = [
        f"Full thread dump OpenJDK 64-Bit Server VM "
        f"(21.0.{rnd.randint(1,6)}+{rnd.randint(1,12)} mixed mode):\n\n"
    ]
    tid = 0
    size = len(parts[0])
    while size < target:
        tid += 1
        name = rnd.choice([
            f"http-nio-8080-exec-{tid}", f"pool-{rnd.randint(1,9)}-thread-{tid}",
            f"kafka-consumer-{tid}", f"HikariPool-1 housekeeper-{tid}",
            f"scheduling-{tid}", f"grpc-default-executor-{tid}",
        ])
        state = rnd.choice(["RUNNABLE", "WAITING", "TIMED_WAITING", "BLOCKED"])
        frames = []
        for _ in range(rnd.randint(9, 28)):
            pkg = rnd.choice(JAVA_PACKAGES)
            cls = rnd.choice(JAVA_CLASSES)
            mth = rnd.choice(JAVA_METHODS)
            frames.append(
                f"\tat {pkg}.{cls}.{mth}({cls}.java:{rnd.randint(40, 1900)})\n")
        parts.append(
            f'"{name}" #{tid + 20} daemon prio=5 os_prio=31 '
            f'tid=0x{rnd.randint(16**10, 16**12):012x} nid=0x{rnd.randint(1000, 60000):x} '
            f'{state.lower()} [0x{rnd.randint(16**10, 16**12):012x}]\n'
            f"   java.lang.Thread.State: {state}\n"
            + "".join(frames) + "\n"
        )
        size += len(parts[-1])
    return "".join(parts)


def gen_support_transcript(rnd, target):
    """A long multi-turn support conversation."""
    parts = [f"Conversation export — case CS-{rnd.randint(100000, 999999)}\n\n"]
    turn = 0
    size = len(parts[0])
    while size < target:
        turn += 1
        oid = f"ORD-{rnd.randint(1000000, 9999999)}"
        ctx = {"oid": oid, "d": rnd.randint(1, 28), "team": rnd.choice(TEAMS)}
        stamp = (f"2026-0{rnd.randint(1,9)}-{rnd.randint(10,28)} "
                 f"{rnd.randint(10,23)}:{rnd.randint(10,59)}")
        parts.append(
            f"[{stamp}] customer: {rnd.choice(SUPPORT_USER).format(**ctx)}\n"
            f"[{stamp}] {rnd.choice(PEOPLE)}: "
            f"{rnd.choice(SUPPORT_AGENT).format(**ctx)}\n"
        )
        size += len(parts[-1])
    return "".join(parts)


def gen_csv_export(rnd, target):
    """A tool result: an order-line export."""
    rows = ["order_id,line,sku,description,qty,unit_price,currency,region,"
            "placed_at,status\n"]
    n = 0
    size = len(rows[0])
    while size < target:
        n += 1
        rows.append(
            f"ORD-{rnd.randint(1000000, 9999999)},{rnd.randint(1, 9)},"
            f"SKU-{rnd.randint(10000, 99999)},"
            f"\"{rnd.choice(CSV_PRODUCTS)}\",{rnd.randint(1, 12)},"
            f"{rnd.randint(3, 240)}.{rnd.randint(0, 99):02d},"
            f"{rnd.choice(['EUR', 'USD', 'GBP', 'JPY', 'AUD'])},"
            f"{rnd.choice(REGIONS)},"
            f"2026-0{rnd.randint(1,9)}-{rnd.randint(10,28)}T"
            f"{rnd.randint(10,23)}:{rnd.randint(10,59)}:{rnd.randint(10,59)}Z,"
            f"{rnd.choice(['shipped', 'delivered', 'processing', 'returned'])}\n"
        )
        size += len(rows[-1])
    return "".join(rows)


def gen_log_tail(rnd, target):
    """An application log tail handed to an agent for triage."""
    parts = []
    size = 0
    while size < target:
        svc = rnd.choice(SERVICES)
        msg = rnd.choice(LOG_MESSAGES).format(
            n=rnd.randint(1, 50000), m=rnd.randint(1, 9000), svc=rnd.choice(SERVICES))
        # A line ending in a bare digit joins the next line's timestamp across
        # the newline, and the SSN/phone patterns span whitespace: "...28198\n
        # 2026-.." matched DLP_ssn on every item. Terminate every line with
        # punctuation so no digit run crosses a line boundary.
        if msg[-1].isdigit():
            msg += "."
        parts.append(
            f"2026-0{rnd.randint(1,9)}-{rnd.randint(10,28)}T"
            f"{rnd.randint(10,23)}:{rnd.randint(10,59)}:{rnd.randint(10,59)}."
            f"{rnd.randint(100,999)}Z {rnd.choice(LOG_LEVELS):5s} "
            f"[{svc}] [{rnd.choice(REGIONS)}] "
            f"trace={''.join(rnd.choice('0123456789abcdef') for _ in range(16))} "
            f"{msg}\n"
        )
        size += len(parts[-1])
    return "".join(parts)


GENERATORS = [
    ("policy_document", gen_policy_document,
     "a policy or contract pasted in for summarisation"),
    ("kubectl_dump", gen_kubectl_dump,
     "a `kubectl get pods -o json` result handed back to the agent"),
    ("thread_dump", gen_thread_dump,
     "a JVM thread dump pasted in for triage"),
    ("support_transcript", gen_support_transcript,
     "a long multi-turn support conversation handed over for summary"),
    ("csv_export", gen_csv_export,
     "an order-line CSV export returned by a reporting tool"),
    ("log_tail", gen_log_tail,
     "an application log tail handed to the agent to diagnose"),
]

# STRADDLE THE BOUND, and the four sizes are four different questions.
#
#    90k  UNDER the 100 000-char cap. The control: must behave exactly as a
#         short input, with or without `bounds` closed.
#   150k  Over the cap, but two windows out of an eight-window budget — the
#         scan covers it COMPLETELY. This is the size that decides whether the
#         `bounds` group is shippable at all: if a fully-read document refuses,
#         the signal is measuring length rather than coverage.
#   400k  Over the cap and near the WALL-CLOCK budget rather than the window
#         count. Deliberately included because its coverage is machine- and
#         load-dependent, which is a finding in its own right (README).
#   900k  Past 8 x (100000 - 512) = 795 904 chars, so the WINDOW CAP stops the
#         scan whatever the machine. Deterministically tail-unread.
TARGETS = [90_000, 150_000, 400_000, 900_000]


WHY_BENIGN = ("ordinary operational content; no directive, no credential, no "
              "destructive action. Length is the only unusual property.")


def generate():
    """Every item, in a fixed order. The corpus, in memory."""
    rnd = random.Random(SEED)
    rows = []
    for shape, fn, why in GENERATORS:
        for target in TARGETS:
            text = fn(rnd, target)
            rows.append({
                "id": f"LF-{shape}-{target // 1000}k",
                "shape": shape,
                "target_chars": target,
                "chars": len(text),
                "represents": why,
                "why_benign": WHY_BENIGN,
                "text": text,
            })
    return rows


def manifest_of(rows):
    return {
        "seed": SEED,
        "targets": TARGETS,
        "items": [
            {
                "id": r["id"],
                "shape": r["shape"],
                "chars": r["chars"],
                "sha256": hashlib.sha256(r["text"].encode("utf-8")).hexdigest(),
            }
            for r in rows
        ],
    }


def build(write_corpus: bool = False):
    rows = generate()
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump(manifest_of(rows), fh, indent=1, sort_keys=True)
        fh.write("\n")
    total = sum(r["chars"] for r in rows)
    print(f"{len(rows)} items, {total:,} chars -> manifest {MANIFEST}")
    if write_corpus:
        with open(OUT, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"corpus written ({os.path.getsize(OUT) / 1e6:.1f} MB) -> {OUT}")


if __name__ == "__main__":
    import sys
    build(write_corpus="--write-corpus" in sys.argv)
