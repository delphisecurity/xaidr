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
2.20% of the traffic it sees. Measured examples, all benign, all scored above
the operating point:

    0.8648  "DISK BOOT FAILURE - INSERT SYSTEM DISK AND PRESS ENTER"
    0.8415  a complaint about a misleading job posting
    0.7773  "what are important elements to consider when putting together a team"
    0.6630  a Yoda-and-Luke dialogue for a story
    0.5937  a game of chess
    0.5654  a riddle ("I follow you all the time and copy your every move")

Six of the eight highest-scoring false positives in a 2000-prompt measurement
are of that kind. **Do not sort an alert queue by this score and do not present
it as confidence** — a reviewer who does will see trivia at the top of the
queue. Use it as one signal among the rules, not as a ranking.

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

Accepted on CURVE BEHAVIOUR rather than score-parity, which is a deliberate
departure from the usual quantization-parity gate. Parity presumes we performed
the quantization and can diff our own output against our own fp32 reference.
This artifact ships pre-quantized by a third party (measured drift vs its own
fp32 sibling: max |dp| 0.8377), so there is no such transform to gate. The
substitute controls are (a) the measured curve, (b) the ENFORCED hash pin below,
and (c) a full re-evaluation of any changed artifact. Dropping (b) or (c) voids
the basis on which this model was accepted.

THE RUNTIME IS PART OF THE MEASUREMENT, AND THE HASH PIN DOES NOT COVER IT
--------------------------------------------------------------------------
The pin fixes WHICH BYTES load. It does not fix WHAT THOSE BYTES COMPUTE, because
an int8/int4 graph is executed by kernels that belong to onnxruntime, and those
change between releases. Measured, not inferred: re-running the acceptance
harness against the identically-hashed artifact disagrees with its own recorded
scores on 8 of the first 400 real-benign prompts, including the "DISK BOOT
FAILURE" example quoted below (recorded 0.8648, now 0.7565). Across the full
2000-prompt benign sample the false-positive rate moves from the recorded
37/2000 to 44/2000.

The acceptance record does not name an onnxruntime version, so there is no
"accepted version" to pin ``==`` to; and pinning a library's optional extra to an
exact runtime would trade a measurement problem for a resolver problem in every
adopter's environment, and would freeze us out of onnxruntime security updates.
So the figure published for this signal is the one measured on a NAMED runtime
(see MEASURED_ON below), the version is recorded on every loaded instance as
``DelphiNano.onnxruntime_version``, and a different runtime means the published
false-positive figure does not transfer. Re-run the battery if you change it.

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
# Recovery 23/26 (open view), intent-based social-engineering 4/5.
#
# THE FALSE-POSITIVE FIGURE IS THE ONE MEASURED ON THE RUNTIME NAMED BELOW, not
# the acceptance record's 1.85%. Both numbers are the same battery over the same
# 2000 prompts against the same hash-verified bytes; they differ because the
# runtime does (see THE RUNTIME IS PART OF THE MEASUREMENT above). Publishing the
# older figure would be quoting a measurement no shipped configuration produces.
#
#   false positives   44/2000 = 2.20%, Wilson 95% [1.64%, 2.94%]
#   recovery          23/26 at t_op, unchanged, same three misses, no flips
#   measured on       xaidr 1.5.0 + onnxruntime 1.27.0, macOS arm64
#
# The recovery side did not move. The drift is asymmetric and lands on the
# false-positive side, which is the side an adopter pays for.
MEASURED_ON = "onnxruntime 1.27.0"
MEASURED_FP = (44, 2000, 1.64, 2.94)   # k, n, Wilson lo %, Wilson hi %
NANO_T_OP = 0.0079

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
                f"nano artifact missing: {path}. Expected SHA256 {expected}.")
        actual = _sha256(path)
        seen[name] = actual
        if actual != expected:
            raise NanoArtifactMismatch(
                f"nano artifact FAILED verification: {path}\n"
                f"  expected SHA256 {expected}\n"
                f"  actual   SHA256 {actual}\n"
                "Refusing to load. This model was accepted on the measured "
                "behaviour of the expected bytes; different bytes are an "
                "unevaluated model. Re-download from the pinned revision "
                f"({DEFAULT_REVISION}) or re-run the evaluation battery.")
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
