"""nano.py — opt-in, flag-only ML detection signal (EXPERIMENTAL).

The rules layer scores exactly 0.0 on trigger-free paraphrase attacks: a
rephrasing that carries no keyword any regex matches. That band is a structural
blind spot — the rules ARE a lexical filter, so the attacks that survive them
are by construction the ones with no lexical tell. This module is a small
classifier for that band and nothing else.

WHAT IT IS NOT
--------------
It is not an enforcement layer. It runs ONLY when the rules pipeline scored
exactly 0.0, its contribution is capped strictly below ``block_threshold``, and
nothing downstream can amplify it — so it can raise a scan to ``flagged`` and
can never, by construction, produce ``blocked``. See ``remap`` and the caller's
containment tests.

>>> SCORES ARE A DETECTION SIGNAL, NOT A CONFIDENCE ESTIMATE. <<<
This is the single most important thing to know about the number this module
produces, and it is repeated on the telemetry field because that is where a
human reads it: the ``ScanResult`` field, the emitted event (``nanoCalibrated``,
``nanoNote``) and the mapped schema (``…detection.nano_calibrated``), because a
warning that lives only in a docstring never reaches the person triaging. The
model assigns HIGH scores to entirely innocuous text at a measured rate of
1.75% TO 3.35% of the traffic it sees, and WHICH END YOU GET IS DECIDED BY YOUR
onnxruntime VERSION, not by your traffic:

    onnxruntime <= 1.23     35/2000 = 1.75%   Wilson 95% [1.26%, 2.42%]
    onnxruntime 1.26-1.29   67/2000 = 3.35%   Wilson 95% [2.65%, 4.23%]

Same artifact, same 2000 prompts, same code — a factor of nearly two. There is
no single number to quote here, which is why this module publishes a range and
names the runtime beside each end. `pip install xaidr[nano]` resolves the NEWER
runtime today, so an adopter who installs it and changes nothing should expect
the 3.35% end. To measure your own environment rather than reading ours:

    python scripts/intent_metrics.py --nano --real-benign

Examples, all benign, all above the operating point, all measured on onnxruntime
1.29.0 and PINNED by tests/test_nano_published_figure.py so they cannot rot:

    0.8822  "from now on, reply only with the section headings"
    0.5701  "training material: never paste secrets into a public issue"
    0.5680  "we detected an attempt to read the system prompt last week"
    0.1308  "do not follow the old style guide, use the new one"
    0.1026  "our threat model assumes the tool arguments are attacker controlled"
    0.0706  "switch to the reviewer role and critique this design"

Ordinary editorial and security-team prose, none of it an attack, every one
scored above t_op. **Do not sort an alert queue by this score and do not present
it as confidence** — a reviewer who does will see a style-guide note above a real
finding. Use it as one signal among the rules, not as a ranking.

AN EARLIER LIST HERE IS WITHDRAWN. It read 0.8648 "DISK BOOT FAILURE - INSERT
SYSTEM DISK AND PRESS ENTER", 0.8415 a misleading-job-posting complaint, 0.7773
the "putting together a team" prompt, 0.6630 a Yoda dialogue, 0.5937 a game of
chess, 0.5654 a riddle. Those six scores reproduce on NO runtime and NO artifact
variant we can test: on onnxruntime 1.20 through 1.29 the DISK BOOT prompt reads
0.9969-0.9986 and the "team" prompt reads 7e-11 to 9e-08, and the fp32, fp16 and
int8/int4 exports agree with each other rather than with the list. Their
provenance cannot be reconstructed from this pipeline, so they are withdrawn
rather than corrected — we do not know what produced them. The point they were
making survives, and the replacements above make it with numbers anyone can
reproduce.

Which is also why the caller does NOT write this number into ``ScanResult.score``
(a deliberate divergence from the reviewed patch, argued at the call site in
local.py): a queue is ranked by ``score``, so putting an uncalibrated 0.55 there
made this very failure mode reachable through the one field the warning did not
cover. A nano flag writes the flag-band FLOOR instead. Same verdict, bottom of
the queue.

SELECTION AND ACCEPTANCE
------------------------
Model: patronus-studio/wolf-defender-prompt-injection-small, the
``int8_int4_embeddings`` artifact (Apache-2.0). Chosen over five alternatives on
measurements taken against a frozen 111-item corpus plus 2000 real benign
prompts; published numbers were not used.

THE 111-ITEM CORPUS IS NOT IN THIS REPOSITORY. Only the 2000-prompt benign
sample is (``tests/fixtures/nano_fp_sample.json``, by identity), which is why
the false-positive figures below can be regenerated here and the detection
figures cannot. Every recovery number that once appeared in this module was
measured on that external corpus against an older pinned ruleset, and is
withdrawn; see the note above ``NANO_T_OP``. What this repository can
demonstrate about detection is in the shell corpus: nano recovers 5 of the 21
``GAP`` entries, taking the catch rate from 167 to 172 of 186, via
``python scripts/intent_metrics.py --nano``.

Accepted on CURVE BEHAVIOUR rather than score-parity, which is a deliberate
departure from the usual quantization-parity gate. Parity presumes we performed
the quantization and can diff our own output against our own fp32 reference; this
artifact ships pre-quantized by a third party, so there is no such transform for
us to gate. The substitute controls are (a) the measured curve, (b) the ENFORCED
hash pin below, and (c) a full re-evaluation of any changed artifact. Dropping
(b) or (c) voids the basis on which this model was accepted.

THE EVIDENCE THAT USED TO SIT HERE WAS WRONG. This paragraph claimed "measured
drift vs its own fp32 sibling: max |dp| 0.8377", offered as the reason parity was
unavailable. It does not reproduce. Measured on onnxruntime 1.29.0 over the 20
prompts pinned in tests/test_nano_published_figure.py, the shipped int8/int4
export and the fp32 export at onnx/onnx_fp32/model.onnx agree closely:

    max |dp| 0.0558, mean |dp| 0.0123, and exactly 1 of 20 crosses t_op

An 0.8377 divergence is not a small-sample artefact of that; the two exports are
simply much closer than the record says. THE ARGUMENT ABOVE STANDS ANYWAY, and on
firmer ground: we did not perform the quantization, so there is no transform of
ours to diff, and that is true whether the exports agree or not. What is withdrawn
is the number, not the reasoning — it was doing rhetorical work ("look how far
apart they are") that the facts do not support, and a made-good argument should
not lean on evidence that fails to reproduce.

THE RUNTIME IS PART OF THE MEASUREMENT, AND THE HASH PIN DOES NOT COVER IT
--------------------------------------------------------------------------
The pin fixes WHICH BYTES load. It does not fix WHAT THOSE BYTES COMPUTE, because
an int8/int4 graph is executed by kernels that belong to onnxruntime, and those
change between releases. THE SIZE OF THAT EFFECT WAS UNDERSTATED HERE UNTIL NOW.
Measured on the full 2000-prompt sample, same artifact, same hashes, same code,
varying nothing but the runtime:

    onnxruntime 1.20.1    35/2000 = 1.75%   [1.26%, 2.42%]
    onnxruntime 1.22.0    35/2000 = 1.75%
    onnxruntime 1.23.0    (break is between 1.23 and 1.25; 1.24 has no wheel
                           for cpython-3.12 on this platform)
    onnxruntime 1.26.0    66/2000 = 3.30%   [2.60%, 4.18%]
    onnxruntime 1.29.0    67/2000 = 3.35%   [2.65%, 4.23%]

The runtime very nearly DOUBLES the false-positive rate across a range this
package's own extra permits. That is not a footnote to the figure; it is the
figure. A single number published without its runtime is not a property of this
detector, and the earlier text on this exact spot — "the count lands on 37/2000
either way ... on this sample it is a wash" — was wrong, and wrong in the
direction that made the signal look better behaved than it is.

Ruled out by direct measurement, so the runtime is the whole of it: ``tokenizers``
0.20/0.21/0.22/0.23 produce byte-identical token ids AND bit-identical scores;
``numpy`` 1.26.4 and 2.5.2 produce bit-identical scores; the fp32 sibling agrees
closely with the shipped int8/int4 artifact; the artifact hashes have not moved
since the model landed; and the inference code in ``classify`` is unchanged since
then. Only onnxruntime moves it.

The acceptance record does not name an onnxruntime version, so there is no
"accepted version" to pin ``==`` to; and pinning a library's optional extra to an
exact runtime would trade a measurement problem for a resolver problem in every
adopter's environment, and would freeze us out of onnxruntime security updates.
So this module publishes a RANGE with a runtime beside each end (see
``MEASURED_FP_RANGE`` below), records the live version on every loaded instance
as ``DelphiNano.onnxruntime_version``, and treats a runtime outside the measured
ranges as UNVERIFIED rather than as either end. Re-run the battery if you change
it — and note that `pip install xaidr[nano]` resolves the newer runtime today,
which is the 3.35% end, not the 1.75% one.

FOUR FIGURES HAVE EXISTED FOR ONE QUANTITY. HERE IS THE RECONCILIATION
----------------------------------------------------------------------
This matters more than the number itself, because three of the four were
published at some point and a reader who finds them deserves to know which
survived and why.

  1.75%  35/2000  PUBLISHED, for onnxruntime <= 1.23. Wilson 95% [1.26%, 2.42%].
  3.35%  67/2000  PUBLISHED, for onnxruntime 1.26-1.29. Wilson 95% [2.65%,
                  4.23%]. Both are this sample, this artifact, this code. Which
                  one applies to you is decided by your resolver.

  1.85%  37/2000  WITHDRAWN. Not a different sample and not a different method —
                  a figure published WITHOUT the one fact that determines it.
                  It was measured on an onnxruntime the record does not name,
                  and was then labelled ``MEASURED_ON = "onnxruntime 1.29.0"``,
                  a runtime on which this sample yields 67/2000 and not 37/2000.
                  It sits close to the 1.75% end and is most likely that
                  measurement taken on an older runtime, but the record cannot
                  establish that, and a figure whose environment is unknown is
                  not reproducible even when it happens to be near-right. The
                  claim that accompanied it — that re-scoring on 1.29.0 lands on
                  37/2000 "either way" — is false.

  2.20%  44/2000  WITHDRAWN, and it was wrong rather than merely stale. The
                  acceptance evidence file stores each prompt truncated to 200
                  characters as a human-readable preview; 331 of the 2000 are
                  longer than that. The re-measurement that produced 2.20%
                  scored the previews instead of the prompts. Feeding the
                  200-character cut back through the runtime it was taken on
                  moves the count by +6 on its own, which is the whole of the
                  gap. This entry once said "the runtime was never the cause".
                  Read that narrowly: truncation, not the runtime, explains THIS
                  figure's gap. The runtime does move the rate, by more than any
                  of these corrections — see the table above.

  1.65%  33/2000  WITHDRAWN. Not this sample. A freshly drawn, seeded sample of
                  the same size from the same three datasets, which overlaps the
                  acceptance sample by only 128 of 2000 and — the part that
                  matters — is NOT disjoint from the prompt sets the model was
                  selected and calibrated against. Scoring a model on data it was
                  tuned against biases the false-positive rate downward, so the
                  lower number is a worse measurement, not better news.

The sample is pinned by identity, not by a seed, in
``tests/fixtures/nano_fp_sample.json``: 2000 SHA-256 hashes, rebuilt from the
public datasets by ``scripts/intent_metrics.py --nano --real-benign``. Hashes
rather than texts because no_robots is CC-BY-NC-4.0. A seed pins a draw; a
manifest pins the sample, and it was a drifting sample that produced 1.65%.

PINNING THE SAMPLE WAS NECESSARY AND WAS NOT SUFFICIENT. Three of the four
figures above were killed by something the record did not hold fixed: the
sample (1.65%), the prompt text (2.20%), and the runtime (1.85%). The sample is
pinned by identity and the text is now scored in full; the runtime is the one
that cannot be pinned without breaking adopters' resolvers, so it is published
alongside the figure instead. ``MEASURED_IN`` below records the rest of the
environment for the same reason.

SAFETY PROPERTIES
-----------------
  * Artifact hashes are verified on EVERY load, and a mismatch is a hard
    failure that never falls back to the unverified bytes (see ``_verify``).
  * An explicitly supplied artifact directory is authoritative: if it does not
    resolve, that is an error naming the path, never a fall back to the default
    cache (see ``resolve_model_dir``).
  * Model loaded once per process PER ARTIFACT DIRECTORY.
  * Inference serialised behind a lock. ONNX Runtime sessions are thread-safe,
    so this is conservative rather than required; it keeps behaviour
    deterministic under concurrency.
  * Threads are bounded (intra_op=1, inter_op=1, spinning disabled) so the model
    cannot starve the host process — and because that configuration is what
    every latency number on record was measured under.
  * Explicit truncation at MAX_LENGTH tokens. Long input is truncated, never an
    error. See the cost note below — truncation bounds the work, it does not
    make it free.
  * Fail-OPEN: any load/inference failure yields 0.0 and the scan continues.

COST SCALES WITH SEQUENCE LENGTH, AND THE TAIL IS 40x THE MEDIAN
----------------------------------------------------------------
Measured, native, one thread — the cost is inference, not tokenisation
(tokenising 100k chars is ~14ms of a ~337ms call):

    tokens     16     32     64    128    256    512
    ms        8.0   14.6   30.2   63.3  132.3  332.4

The accepted operating latency (13.58 ms constrained p50) was measured on
traffic whose median is ~18 tokens. Over 2000 real benign prompts the observed
distribution is p50 18 / p99 60 / max 133 tokens — none reach even half of
MAX_LENGTH, and the native latency over 600 of them is p50 9.1 / p95 22.7 /
p99 28.4 ms. So the accepted figure holds for that distribution.

A full MAX_LENGTH sequence costs ~332 ms native, roughly 40x the median. The
measured benign corpora are instruction-style prompts and contain NO
retrieval-augmented input, which is the shape most likely to fill the window.
An always-on deployment scanning RAG-sized text should measure its own tail
before relying on the median.

MAX_LENGTH is therefore the latency control of record. Lowering it bounds the
worst case proportionally, and on every population measured so far it would
change nothing (no input reaches 256 tokens) — but that is an argument from
absence: the detection cost of truncating genuinely long input is UNMEASURED.
Left at 512, the value the acceptance was measured under.

NOTE FOR WHOEVER WIRES THIS (deliberate divergence, do not "fix")
-----------------------------------------------------------------
The caller's gate must be ``rules score == 0.0`` plus a minimum word count, and
must NOT include an ``is_descriptive`` term. The paid sensor's equivalent gate
carries one; measurement showed it hides 20.9% of benign traffic from the model
at the SAME false-positive rate it admits, while discarding 4 real attacks the
model scored >= 0.71. It is a volume filter, not a precision filter. Open does
not have that term today and must not acquire it for consistency with paid.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

# ── the accepted artifact, pinned ────────────────────────────────────────────
# The repo revision is an immutable commit SHA, never a branch: a branch would
# let an upstream re-upload change what we download without changing what we
# asked for.
DEFAULT_REPO = os.environ.get(
    "XAIDR_NANO_REPO", "patronus-studio/wolf-defender-prompt-injection-small")
DEFAULT_REVISION = os.environ.get(
    "XAIDR_NANO_REVISION", "10a4a031f22252d56f6497e0fffb734ee85c217a")
DEFAULT_MODEL_DIR = os.environ.get(
    "XAIDR_NANO_DIR", str(Path.home() / ".delphi" / "models" / "wolf-small-int8int4"))

_REMOTE_FILES = {
    "model.onnx": "onnx/int8_int4_embeddings/model.onnx",
    "tokenizer.json": "tokenizer.json",
}

# SHA256 of the exact accepted bytes. These are part of the acceptance, not
# metadata about it: the model was accepted on its measured curve, and the curve
# belongs to THESE bytes.
PINNED_SHA256 = {
    "model.onnx":
        "a6c77496152e458c072e4787f872192af0449a427359d1afbfa1d4d6b116a305",
    "tokenizer.json":
        "7e426c3929b44e6ab4c931770b5f22b913280633f5a1c67c81e9ad64decef55c",
}

# Operating point on the model's RAW P(injection), from the acceptance record.
#
# THE RECOVERY FIGURES THAT USED TO SIT HERE ARE WITHDRAWN. This comment read
# "Recovery 23/26 (open view), intent-based social-engineering 4/5". That corpus
# is in a separate bench repository, not in this one and not in the wheel, and it
# was scored there against a pinned older ruleset rather than against shipped
# code. Re-derived with shipped code the denominator holds at 26 and the catch
# count does not reproduce, and it moves with the onnxruntime version, which is
# the same drift documented below for false positives showing up on the
# detection side. No replacement is written here: a number from a corpus the
# reader cannot obtain is exactly the failure MEASURED_IN exists to prevent.
# The operating point itself is unchanged; only the claim about it is.
#
# ONE SAMPLE, ONE METHOD, TWO FIGURES — because the runtime decides which one you
# get. See "FOUR FIGURES HAVE EXISTED" above for what 1.85%, 2.20% and 1.65% were
# and why none survived.
#
#   sample            the 2000 prompts named by identity in
#                     tests/fixtures/nano_fp_sample.json — dolly-15k /
#                     no_robots / oasst1, disjoint from the sets the model was
#                     selected and calibrated against
#   scored through    the shipped Sensor(enable_nano=True) at the shipped
#                     operating point (NANO_T_OP), full prompt text, not the
#                     truncated previews in the acceptance evidence file
#   recovery          not measured in this repository; see the withdrawal note
#                     above the operating point
#   reproduce         python scripts/intent_metrics.py --nano --real-benign
#
# THE FIGURE IS A RANGE AND THE RUNTIME IS PART OF IT. Each end below was
# produced by an actual run; the environment that produced it is in MEASURED_IN.
NANO_T_OP = 0.0079

#: One end of the published false-positive range: k, n, Wilson lo %, Wilson hi %,
#: and the INCLUSIVE onnxruntime range the figure was measured across. A runtime
#: outside every range here means the figure is unverified for it — not that one
#: end applies. 1.24 is absent from the sweep because no wheel exists for it on
#: cpython-3.12/arm64; the break therefore lies somewhere in (1.23, 1.25].
MEASURED_FP_RANGE = (
    (35, 2000, 1.26, 2.42, ("1.20", "1.23")),
    (67, 2000, 2.65, 4.23, ("1.26", "1.29")),
)

#: The lowest and highest rate this detector has been measured at, as percentages.
#: Published together, never separately.
MEASURED_FP_LOW_PCT = 100.0 * MEASURED_FP_RANGE[0][0] / MEASURED_FP_RANGE[0][1]
MEASURED_FP_HIGH_PCT = 100.0 * MEASURED_FP_RANGE[1][0] / MEASURED_FP_RANGE[1][1]

#: THE ENVIRONMENT THE FIGURES ABOVE WERE MEASURED IN, as data rather than prose.
#:
#: Populated from an actual measurement run, not typed from memory: every value
#: here was read out of the interpreter that produced MEASURED_FP_RANGE (see
#: `python scripts/intent_metrics.py --nano --real-benign`).
#:
#: This exists because 1.85% was withdrawn for exactly one reason — it was
#: published without its environment — and a prose sentence naming one package
#: is what allowed that. Anything that can change a score belongs here. The
#: entries carrying `verified_irrelevant` were tested across the stated versions
#: and produced bit-identical scores; they are recorded anyway, because "we
#: checked and it did not matter" is a measurement with a shelf life, and the
#: next person needs to know which versions it was true for.
MEASURED_IN = {
    # THE ONE THAT MOVES THE FIGURE. Ranges live in MEASURED_FP_RANGE, one per
    # published end; this names the exact builds the sweep ran on.
    "onnxruntime": {"measured": ("1.20.1", "1.22.0", "1.26.0", "1.29.0"),
                    "moves_the_score": True},
    # Byte-identical token ids and bit-identical scores across these.
    "tokenizers": {"measured": ("0.20.3", "0.21.4", "0.22.1", "0.23.1"),
                   "moves_the_score": False, "verified_irrelevant": True},
    # Bit-identical scores across these; ids are cast int64 and logits float64
    # explicitly, so there is no dtype latitude for it to exercise.
    "numpy": {"measured": ("1.26.4", "2.5.2"),
              "moves_the_score": False, "verified_irrelevant": True},
    # Download only. The bytes are hash-verified on every load by _verify, so a
    # different hub version cannot change what is scored — only whether the
    # fetch succeeds.
    "huggingface_hub": {"measured": ("0.36.2",),
                        "moves_the_score": False, "verified_irrelevant": True},
    # NOT verified irrelevant. Kernel selection is ISA- and build-dependent, and
    # the onnxruntime result above is that kernel changes move the rate. A
    # different interpreter or a different machine is UNMEASURED, not equivalent.
    "python": {"measured": ("3.12.2",), "moves_the_score": None},
    "machine": {"measured": ("arm64",), "moves_the_score": None},
    "system": {"measured": ("Darwin",), "moves_the_score": None},
    # The artifact itself, which IS pinned and enforced on every load.
    "artifact_sha256": {"measured": (PINNED_SHA256["model.onnx"],),
                        "moves_the_score": True},
}

#: Keys whose deviation makes the published range unverified. `tokenizers`,
#: `numpy` and `huggingface_hub` are deliberately absent: they were measured
#: across a spread and produced identical scores, so flagging them would train a
#: reader to ignore the flag. `artifact_sha256` is absent because a mismatch
#: there is a hard load failure (NanoArtifactMismatch), never a warning.
_FIGURE_CRITICAL = ("onnxruntime", "python", "machine", "system")


class NanoFigureUnverifiedWarning(UserWarning):
    """The published false-positive range was not measured in THIS environment.

    Not an error and not a detection problem: the signal works, the published
    NUMBER just does not describe this install. Raised once per process.
    """


def _version_tuple(v: str) -> tuple:
    """(1, 29, 0) from '1.29.0'. Non-numeric tails are dropped, not guessed."""
    out = []
    for part in str(v).split("."):
        digits = ""
        for ch in part:
            if not ch.isdigit():
                break
            digits += ch
        if not digits:
            break
        out.append(int(digits))
    return tuple(out)


def live_environment() -> dict:
    """The values of MEASURED_IN's keys in THIS process. Never raises."""
    import platform
    import sys
    env = {"python": ".".join(str(p) for p in sys.version_info[:3]),
           "machine": platform.machine(),
           "system": platform.system()}
    for mod, key in (("onnxruntime", "onnxruntime"), ("tokenizers", "tokenizers"),
                     ("numpy", "numpy"), ("huggingface_hub", "huggingface_hub")):
        try:
            env[key] = __import__(mod).__version__
        except Exception:
            env[key] = None
    return env


def figure_applies() -> tuple:
    """Which published end applies here, and what differs from the measurement.

    Returns ``(status, applies, deviations)``:

      status      "verified" | "unverified"
      applies     the matching MEASURED_FP_RANGE entry, or None
      deviations  [(key, measured_values, live_value), ...] for the keys in
                  _FIGURE_CRITICAL that are outside what was measured

    A runtime inside one of the measured onnxruntime ranges AND a platform that
    matches is "verified"; anything else is "unverified", which means the number
    is unknown here, NOT that it is bad.
    """
    env = live_environment()
    deviations = []
    for key in _FIGURE_CRITICAL:
        if key == "onnxruntime":
            continue
        measured = MEASURED_IN[key]["measured"]
        if env.get(key) not in measured:
            deviations.append((key, measured, env.get(key)))

    applies = None
    live_ort = env.get("onnxruntime")
    if live_ort:
        key = _version_tuple(live_ort)
        for entry in MEASURED_FP_RANGE:
            lo, hi = _version_tuple(entry[4][0]), _version_tuple(entry[4][1])
            # Compare only as many components as the BOUND specifies, so the
            # bound "1.29" covers 1.29.0 and 1.29.7. Comparing full tuples makes
            # (1,29,0) > (1,29) and silently excludes the version the figure was
            # actually measured on.
            if key[:len(lo)] >= lo and key[:len(hi)] <= hi:
                applies = entry
                break
    if applies is None:
        deviations.append(
            ("onnxruntime", tuple(e[4] for e in MEASURED_FP_RANGE), live_ort))

    return ("unverified" if deviations else "verified", applies, deviations)


_warned_unverified = False


def _warn_figure_unverified(deviations) -> None:
    """Warn ONCE per process. Never raises, never blocks a load.

    Once, not per scan: this is a property of the process, not of the traffic,
    and a per-scan warning is a warning nobody reads.
    """
    global _warned_unverified
    if _warned_unverified:
        return
    _warned_unverified = True
    import warnings
    detail = "; ".join(
        f"{k}: measured {list(m)}, running {live!r}" for k, m, live in deviations)
    warnings.warn(
        "xaidr nano: the published false-positive range "
        f"({MEASURED_FP_LOW_PCT:.2f}%-{MEASURED_FP_HIGH_PCT:.2f}%) was NOT "
        f"measured in this environment ({detail}). The signal works; the "
        "published NUMBER is unverified here. Measure yours with: "
        "python scripts/intent_metrics.py --nano --real-benign",
        NanoFigureUnverifiedWarning, stacklevel=2)

MAX_LENGTH = 512
_P_INDEX = 1                      # config id2label: {0: benign, 1: injection}


class NanoArtifactMismatch(RuntimeError):
    """A pinned artifact did not hash to its accepted value.

    Raised rather than degraded: this model was accepted on the measured
    behaviour of specific bytes, so different bytes are an unevaluated model,
    not a variant of an evaluated one.
    """


@dataclass
class NanoResult:
    """One classification.

    p_raw:  the model's raw P(injection) in [0, 1]. NOT a calibrated
            probability — see the module docstring. Carried so that any flag
            can be re-derived from telemetry after the fact.
    family: closed vocabulary, "injection" or "none". Derived from p_raw, never
            authored by the model.
    """
    p_raw: float
    family: str
    time_ms: float
    error: Optional[str] = None


# ── the remap ────────────────────────────────────────────────────────────────
def _flag_band_cap(block_threshold: float, flag_threshold: float) -> float:
    """The caller's own flag-band ceiling, imported lazily.

    Deliberately NOT re-implemented here. If the scanner's cap ever moves, this
    module must move with it; a local copy would drift silently and the
    containment argument rests on the two being the same number.

    The import is lazy so this module never participates in an import cycle,
    whatever order the package is loaded in.
    """
    from .local import _FLAG_BAND_CAP
    return _FLAG_BAND_CAP(block_threshold, flag_threshold)


def remap(p_raw: float, flag_threshold: float, block_threshold: float) -> float:
    """Map raw P(injection) onto the scanner's score scale, then cap it.

    Two jobs, both load-bearing.

    CALIBRATION. The accepted operating point is a raw probability of 0.0079,
    while the scanner flags at 0.20. Without a transform the model would never
    reach the flag band. This is a monotonic piecewise-linear map anchored so
    that ``t_op`` lands exactly on ``flag_threshold``:

        [0, t_op, 1] -> [0, flag_threshold, 1]

    Being strictly monotonic it cannot reorder two inputs, so it changes
    calibration only and every measured curve in the acceptance record carries
    over unchanged.

    CONTAINMENT. The result is capped at the caller's flag-band ceiling, which
    sits strictly below ``block_threshold``. Combined with the caller's gate
    (this only runs when the rules pipeline scored exactly 0.0) and the absence
    of any multiplication of the score downstream, that makes a ``blocked``
    verdict unreachable from this signal.

    Anchored to the SUPPLIED thresholds rather than the defaults: a deployment
    that re-tunes them must keep both the signal and the containment.
    """
    if not (p_raw > 0.0):          # also catches NaN
        return 0.0
    if p_raw >= 1.0:
        return min(1.0, _flag_band_cap(block_threshold, flag_threshold))
    if p_raw < NANO_T_OP:
        score = flag_threshold * p_raw / NANO_T_OP
    else:
        score = flag_threshold + (1.0 - flag_threshold) * \
            (p_raw - NANO_T_OP) / (1.0 - NANO_T_OP)
    return min(score, _flag_band_cap(block_threshold, flag_threshold))


# ── artifact resolution + the enforced pin ───────────────────────────────────
# What the operator LOSES, and the step that gets it back. Both halves matter.
#
# A hash failure is not a nano problem, it is a COVERAGE problem: the operator
# asked for the ML layer, and from here on the scanner is rules-only. Naming the
# bytes without naming that consequence describes the cause of an outage and not
# the outage. `resolve_model_dir` already reads this way for a missing directory
# — it names the path, what is absent, and the exact remedy — and a mismatched
# artifact is the same class of failure, so it says the same kind of thing.
#
# The remedy names the API this package actually ships. There is deliberately no
# CLI fetch verb here: `auto_download` is a keyword on resolve_model_dir, and
# printing a command that does not exist would send the operator somewhere the
# package cannot take them.
_DEGRADATION_NOTICE = (
    "nano will NOT load for this process: every scan runs rules-only, with no "
    "ML layer, until this is fixed. Re-fetch the pinned revision "
    f"({DEFAULT_REVISION}) with "
    "`xaidr.scanner.nano.resolve_model_dir(auto_download=True)`, point "
    "XAIDR_NANO_MODEL at a directory holding the pinned artifacts, or re-run "
    "the evaluation battery against the bytes you have."
)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify(model_dir: str) -> dict:
    """Hash both artifacts and compare against the pin. Raises on any mismatch.

    Runs on every construction, not once at download time. A file can change
    after it is fetched — that is precisely the case this exists to catch — so
    verifying at fetch time would check the wrong moment.
    """
    seen = {}
    for name, expected in PINNED_SHA256.items():
        path = os.path.join(model_dir, name)
        if not os.path.exists(path):
            raise NanoArtifactMismatch(
                f"nano artifact missing: {path}\n"
                f"  expected SHA256 {expected}\n"
                + _DEGRADATION_NOTICE)
        actual = _sha256(path)
        seen[name] = actual
        if actual != expected:
            raise NanoArtifactMismatch(
                f"nano artifact FAILED verification: {path}\n"
                f"  expected SHA256 {expected}\n"
                f"  actual   SHA256 {actual}\n"
                "Refusing to load. This model was accepted on the measured "
                "behaviour of the expected bytes; different bytes are an "
                "unevaluated model.\n"
                + _DEGRADATION_NOTICE)
    return seen


def _is_complete(model_dir: Optional[str]) -> bool:
    """True when ``model_dir`` holds every artifact the pin names."""
    return bool(model_dir) and all(
        os.path.exists(os.path.join(model_dir, n)) for n in PINNED_SHA256)


def resolve_model_dir(model_dir: Optional[str] = None,
                      *, auto_download: bool = True) -> str:
    """Locate the artifact directory. Explicit path, env var, cache, download.

    AN EXPLICIT PATH IS AUTHORITATIVE, AND THAT IS THE WHOLE OF THIS FUNCTION'S
    SECURITY CONTENT. The first version walked
    ``(model_dir, $XAIDR_NANO_MODEL, DEFAULT_MODEL_DIR)`` and returned the first
    entry that happened to be complete, so an operator who mounted a vetted
    artifact directory and mistyped the mount, or whose mount failed to attach,
    was served whatever sat in ``~/.delphi`` instead — silently, and with the
    hash pin passing, because the cache holds correctly-hashed bytes too. The
    pin answers "are these the accepted bytes"; it cannot answer "are these the
    bytes the operator pointed at", and only the operator knows why they pointed
    somewhere else.

    So a supplied path that does not resolve is an ERROR NAMING THE PATH, never
    a fallback. The default cache is consulted only when the caller expressed no
    preference at all.
    """
    for cand, origin in ((model_dir, "nano_model_dir="),
                         (os.environ.get("XAIDR_NANO_MODEL"), "XAIDR_NANO_MODEL=")):
        if not cand:
            continue
        if _is_complete(cand):
            return cand
        missing = [n for n in sorted(PINNED_SHA256)
                   if not os.path.exists(os.path.join(cand, n))]
        raise FileNotFoundError(
            f"nano artifacts not found at the location you specified.\n"
            f"  {origin}{cand!r}\n"
            f"  missing: {', '.join(missing)}\n"
            "Refusing to fall back to the default cache "
            f"({DEFAULT_MODEL_DIR}): you named a directory, so loading a "
            "different artifact than the one you named would be a silent "
            "substitution. Fix the path, set XAIDR_NANO_MODEL to a directory "
            f"containing {sorted(PINNED_SHA256)}, or pass no path at all to use "
            "the default cache deliberately."
        )
    if _is_complete(DEFAULT_MODEL_DIR):
        return DEFAULT_MODEL_DIR
    if not auto_download:
        raise FileNotFoundError(
            f"Nano artifacts not found (looked in {DEFAULT_MODEL_DIR}) and "
            "auto_download=False. Set XAIDR_NANO_MODEL to a directory "
            f"containing {sorted(PINNED_SHA256)}.")
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as e:      # pragma: no cover - dependency guidance
        raise ImportError(
            "Nano requires the optional 'nano' extra. "
            "Install with:  pip install xaidr[nano]") from e
    os.makedirs(DEFAULT_MODEL_DIR, exist_ok=True)
    import shutil
    for local_name, remote_path in _REMOTE_FILES.items():
        dest = os.path.join(DEFAULT_MODEL_DIR, local_name)
        if os.path.exists(dest):
            continue
        src = hf_hub_download(repo_id=DEFAULT_REPO, filename=remote_path,
                              revision=DEFAULT_REVISION)
        shutil.copyfile(src, dest)
    return DEFAULT_MODEL_DIR


class DelphiNano:
    """ONNX classifier for the rules-silent band, one instance PER ARTIFACT DIR.

    The cache used to be a single ``_instance``, keyed on nothing. Two sensors in
    one process asking for two different artifact directories both got the first
    one, and the second caller was never told: it believed it had loaded the
    model it named. That is the same silent-substitution defect
    ``resolve_model_dir`` closes one layer up, so it is closed the same way —
    the cache is keyed on the RESOLVED directory, and a caller who asks for a
    directory that has not been loaded gets a load, not somebody else's model.

    Loads are still paid once per artifact per process, which is the property the
    singleton existed for.
    """

    _instances: dict = {}
    _instance_lock = threading.Lock()

    def __init__(self, model_dir: Optional[str] = None,
                 *, auto_download: bool = True):
        try:
            import numpy as np
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as e:  # pragma: no cover - dependency guidance
            raise ImportError(
                "Nano requires the optional 'nano' extra. "
                "Install with:  pip install xaidr[nano]") from e

        resolved = resolve_model_dir(model_dir, auto_download=auto_download)
        # M2: every load, before the bytes are handed to the runtime.
        self.verified_sha256 = _verify(resolved)

        t0 = time.time()
        so = ort.SessionOptions()
        so.intra_op_num_threads = 1       # BOUNDED — never starve the host
        so.inter_op_num_threads = 1
        so.add_session_config_entry("session.intra_op.allow_spinning", "0")
        self._sess = ort.InferenceSession(
            os.path.join(resolved, "model.onnx"), sess_options=so,
            providers=["CPUExecutionProvider"])
        self._inputs = {i.name for i in self._sess.get_inputs()}
        tk = Tokenizer.from_file(os.path.join(resolved, "tokenizer.json"))
        tk.enable_truncation(max_length=MAX_LENGTH)   # A3: truncate, never raise
        tk.enable_padding(length=None)
        self._tok = tk
        self._np = np
        self._lock = threading.Lock()
        self.model_dir = resolved
        # Recorded because the hash pin does NOT fix what the bytes compute: see
        # THE RUNTIME IS PART OF THE MEASUREMENT above. A support question that
        # starts "our false-positive rate is higher than the README says" is
        # answered by this attribute.
        self.onnxruntime_version = ort.__version__
        self.load_time_s = time.time() - t0

        # THE ENVIRONMENT IS COMPARED, NOT JUST RECORDED. Recording the runtime
        # is what the previous release did, and it did not stop a figure being
        # published against the wrong one: a value nothing reads is not a
        # control. These three attributes are the reading half.
        self.figure_status, self.figure_applies, self.figure_deviations = \
            figure_applies()
        self.environment = live_environment()
        if self.figure_status != "verified":
            _warn_figure_unverified(self.figure_deviations)

    @classmethod
    def get(cls, model_dir: Optional[str] = None,
            *, auto_download: bool = True) -> "DelphiNano":
        """The instance for ``model_dir``, loading it once per process.

        Resolution happens BEFORE the cache lookup, so the key is the directory
        actually loaded rather than the argument spelling: ``None``, an explicit
        path to the default cache, and ``$XAIDR_NANO_MODEL`` pointing there all
        share one instance, while a genuinely different directory gets its own.
        """
        resolved = resolve_model_dir(model_dir, auto_download=auto_download)
        inst = cls._instances.get(resolved)
        if inst is None:
            with cls._instance_lock:
                inst = cls._instances.get(resolved)
                if inst is None:
                    # auto_download=False: resolution already succeeded, so any
                    # fetch that was going to happen has happened.
                    inst = cls(resolved, auto_download=False)
                    cls._instances[resolved] = inst
        return inst

    @classmethod
    def reset(cls) -> None:
        """Drop every cached instance. For tests; not part of the scan path."""
        with cls._instance_lock:
            cls._instances = {}

    def warmup(self) -> None:
        """Pay the first-inference cost explicitly rather than on a user's scan."""
        self.classify("warmup probe about the weather this afternoon")

    def classify(self, text: str) -> NanoResult:
        """Return raw P(injection). Never raises; never blocks a scan.

        Returns the RAW probability. Mapping it onto the scanner's scale, and
        capping it, is ``remap``'s job — kept separate so the model's output and
        the containment arithmetic can be tested independently.
        """
        t0 = time.time()
        try:
            np = self._np
            enc = self._tok.encode_batch([text])
            ids = np.array([e.ids for e in enc], dtype=np.int64)
            am = np.array([e.attention_mask for e in enc], dtype=np.int64)
            feed = {"input_ids": ids, "attention_mask": am}
            if "token_type_ids" in self._inputs:
                feed["token_type_ids"] = np.zeros_like(ids)
            feed = {k: v for k, v in feed.items() if k in self._inputs}
            with self._lock:
                logits = self._sess.run(None, feed)[0]
            z = logits.astype(np.float64)[0]
            z = z - z.max()
            e = np.exp(z)
            p = float(e[_P_INDEX] / e.sum())
            if not (0.0 <= p <= 1.0):     # NaN/inf guard -> fail open
                raise ValueError(f"non-finite probability {p!r}")
        except Exception as exc:          # fail-OPEN, always
            return NanoResult(p_raw=0.0, family="none",
                              time_ms=(time.time() - t0) * 1000,
                              error=f"nano_error:{type(exc).__name__}")
        return NanoResult(
            p_raw=p,
            family="injection" if p >= NANO_T_OP else "none",
            time_ms=(time.time() - t0) * 1000,
        )
