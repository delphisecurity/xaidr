"""The fail-closed option: four groups, each opt-in, all open by default.

WHY FOUR GROUPS AND NOT ONE SWITCH. A corrupt rules file, a crashed extension,
a malformed policy and an oversized input want different answers, and one
boolean would force the operator to accept the worst of them to get the best.
The groups are keyed on WHO CAN FIX THE FAULT AND WHEN, which is the only
partition that makes each group independently safe to enable:

``artifact``
    The sensor is not the sensor the operator configured — a rule asset failed
    to load, a named policy file is unreadable, a rule's regex would not
    compile. Closed means **the sensor refuses to CONSTRUCT**. It does NOT mean
    traffic blocks, and that distinction is the whole reason this group exists
    separately. A corrupt ``all-l1-rules.json`` says nothing about the content
    of any request, so answering a request with ``blocked`` would be a claim
    the sensor cannot support; it would also convert a packaging defect into a
    customer-found outage, at a moment when the operator has no signal saying
    which file is broken. Raising at construction puts the fault in a deploy
    log, once, with the asset named. That is the same ADV-2 posture seven
    constructor arguments already take (``enforcement_mode``,
    ``privilege_tier``, ``circuit_breaker``, ``extensions``, the nano artifact
    hash, a duplicate policy-condition key, ``a2a_structural_enforcement``).

``controls``
    A control the OPERATOR INSTALLED did not run — an extension hook raised, an
    escalator timed out, a breaker counter is inert. Closed means the call is
    refused, because the verdict was computed without a control the deployment
    paid for. On a bare sensor this group is a no-op by construction: there are
    no extensions, no escalators, no breaker and no patched seams, so nothing
    can report a control fault. That property is what makes it the first group
    an operator should enable.

``bounds``
    An INPUT defeated a parser bound — nesting past the A2A walk depth, a
    document past the L1 window budget, a batch past ``MAX_STATEMENTS``, an
    argument tree past the candidate cap. This is the only group whose trigger
    is an attacker's LEVER rather than an accident, and the only one with a
    real false-positive cost on honest traffic. See
    ``docs/fail-closed-design.md`` §e for what that cost measures at.

``internal``
    The sensor's own code raised. Closed means block. Recommended LAST: the
    trigger is a bug in this package, so enabling it bets the host's
    availability on our test coverage.

WHAT EACH GROUP RETURNS is deliberately NOT a new type. See
``docs/fail-closed-design.md`` §c: a correct verdict travelling a return path
whose contract it did not satisfy is what crashed a LangGraph host in 1.9.0.
A fail-closed decision produces an ordinary :class:`ScanResult` with
``action="blocked"`` (or ``"approval_required"``) and rides the refusal path
each boundary already has — ``refusal_text``/``_langchain_refusal`` at tool
seams, ``DelphiBlockedError`` at entrypoint and transport seams. No new return
path is added anywhere.

FAIL-CLOSED COMPOSES WITH ``enforcement_mode`` AND NEVER OVERRIDES IT. Every
fail-closed verdict goes through ``_apply_mode``, so in monitor mode it is
softened to ``flagged`` exactly as a content block is. An option that silently
turned monitor into block would be a worse defect than the one it fixes.
"""

from __future__ import annotations

import difflib
from typing import Mapping, Optional, Sequence

__all__ = [
    "GROUPS",
    "FAIL_CLOSED_CATEGORY",
    "FAIL_CLOSED_RULES",
    "FailClosedError",
    "FailClosedConfig",
    "resolve",
    "AssetFault",
    "record_asset_fault",
    "asset_faults",
    "clear_asset_faults",
]

#: The four groups, in the order an operator should consider enabling them.
GROUPS = ("artifact", "controls", "bounds", "internal")

#: Verdicts a group may resolve to. ``artifact`` accepts neither: it refuses to
#: construct, and there is no action to approve when the fault predates every
#: request.
VERDICTS = ("blocked", "approval_required")

#: One category for every fail-closed verdict, so a SIEM rule keys on one
#: string. The GROUP is in the rule id and in the telemetry, which is where the
#: distinction an operator acts on belongs.
FAIL_CLOSED_CATEGORY = "fail_closed"

FAIL_CLOSED_RULES = {
    "controls": "FAIL_CLOSED_CONTROL_FAULT",
    "bounds": "FAIL_CLOSED_BOUND_EXCEEDED",
    "internal": "FAIL_CLOSED_INTERNAL_FAULT",
}


class FailClosedError(Exception):
    """Raised INTERNALLY at a fault site when its group is closed.

    Never reaches a caller: every scan entry point converts it into a verdict.
    It exists so a fault deep in a hook chain can reach the entry point without
    every intermediate frame having to thread a status back up — the same
    reason ``_ExtensionContractError`` is an exception rather than a return
    value.

    Deliberately NOT a subclass of ``_ExtensionContractError``. That class means
    "an extension did something the seam forbids, and proceeding would be acting
    on a control that is not enforcing", and it is re-raised to the caller
    unconverted. This one means "a control did not run and the operator asked to
    refuse in that case", which is a VERDICT, and a verdict must travel the
    verdict path.
    """

    def __init__(self, group: str, detail: str):
        self.group = group
        self.detail = detail
        super().__init__(f"fail-closed [{group}]: {detail}")


class FailClosedConfig:
    """Which groups are closed, and what verdict each one produces.

    Immutable. ``group in config`` is the only question the hot path asks, and
    it is a dict lookup on an empty dict in the default configuration.
    """

    __slots__ = ("_verdicts",)

    def __init__(self, verdicts: Mapping[str, str]):
        self._verdicts = dict(verdicts)

    def __contains__(self, group: str) -> bool:
        return group in self._verdicts

    def __bool__(self) -> bool:
        return bool(self._verdicts)

    def verdict(self, group: str) -> str:
        """The action this group produces. ``"blocked"`` unless overridden."""
        return self._verdicts.get(group, "blocked")

    @property
    def groups(self) -> tuple:
        """The closed groups, in ``GROUPS`` order."""
        return tuple(g for g in GROUPS if g in self._verdicts)

    def as_dict(self) -> dict:
        """``{group: verdict}`` — what the manifest and telemetry publish."""
        return dict(self._verdicts)

    def __repr__(self) -> str:
        return f"FailClosedConfig({self._verdicts!r})"


#: The default: every group open. Shared, so the common case allocates nothing.
OPEN = FailClosedConfig({})


def _unknown(name, valid, what: str) -> str:
    near = difflib.get_close_matches(str(name), sorted(valid), n=1, cutoff=0.5)
    hint = f" Did you mean {near[0]!r}?" if near else ""
    return (
        f"fail_closed: unknown {what} {name!r}.{hint} "
        f"Valid {what}s: {', '.join(sorted(valid))}."
    )


def resolve(fail_closed) -> FailClosedConfig:
    """Normalise the ``fail_closed=`` constructor argument. Raises on anything
    it does not understand.

    Accepts

    * ``()`` / ``None`` — the default, every group open
    * a sequence of group names — each resolves to ``"blocked"``
    * a mapping of group name to verdict — for a deployment that already routes
      ``approval_required`` to a human

    LOUD VALIDATION, per ADV-2: a security control handed a value it does not
    understand must fail at construction rather than defaulting to inert. A
    misspelled ``fail_closed=("bonuds",)`` that quietly did nothing would leave
    a deployment believing it had a posture it does not have, which is exactly
    the failure this option exists to remove.
    """
    if fail_closed is None or fail_closed == ():
        return OPEN

    if isinstance(fail_closed, FailClosedConfig):
        return fail_closed

    if isinstance(fail_closed, (str, bytes)):
        raise ValueError(
            "fail_closed must be a sequence or mapping of group names, got a "
            f"{type(fail_closed).__name__}. A bare string is rejected because "
            "fail_closed='bounds' and fail_closed=('bounds',) would otherwise "
            f"differ only by a comma. Valid groups: {', '.join(GROUPS)}."
        )

    if isinstance(fail_closed, Mapping):
        items = list(fail_closed.items())
    elif isinstance(fail_closed, (list, tuple, set, frozenset)):
        items = [(g, "blocked") for g in fail_closed]
    else:
        raise ValueError(
            "fail_closed must be a sequence or mapping of group names, got "
            f"{type(fail_closed).__name__}. "
            f"Valid groups: {', '.join(GROUPS)}."
        )

    verdicts: dict = {}
    for group, verdict in items:
        if group not in GROUPS:
            raise ValueError(_unknown(group, GROUPS, "group"))
        if verdict not in VERDICTS:
            raise ValueError(_unknown(verdict, VERDICTS, "verdict"))
        if group == "artifact" and verdict != "blocked":
            # There is no action to approve. The fault predates every request,
            # so there is no per-action approver to route to and nothing to
            # route. Accepting the value would publish a posture that cannot
            # exist.
            raise ValueError(
                "fail_closed: group 'artifact' does not accept a verdict. It "
                "refuses to CONSTRUCT the sensor rather than producing a "
                "verdict on traffic — a corrupt rule asset says nothing about "
                "the content of any request, and there is no action for an "
                "approver to approve. Use fail_closed=('artifact',) or the "
                "mapping form {'artifact': 'blocked'}; 'approval_required' is "
                "not available for this group."
            )
        verdicts[group] = verdict
    return FailClosedConfig(verdicts)


# ── asset fault registry ─────────────────────────────────────────────────────
# WHY A REGISTRY AND NOT A RETURN VALUE. The rule assets load at MODULE IMPORT
# (`l1.INPUT_RULES = _detectors_first(_load_and_compile(...))` runs at import
# time), long before any sensor is constructed and with no caller to return a
# status to. Before this registry the four loaders reported a corrupt asset by
# `print`ing to stdout, which nothing reads and no host pipeline captures as an
# error — a security control degrading to inert with the notification written
# to a stream nobody is watching.
#
# THE FAULT POINT AND THE FAIL-CLOSED POINT ARE NOT THE SAME PLACE, and they
# cannot be. `import xaidr` must not crash a host over a corrupt asset — that
# is the posture `l1._load_and_compile` has always documented and it stays. So
# the loader RECORDS, import still succeeds, and `DelphiSensor.__init__` is
# where the operator's `artifact` choice is applied. See §f of
# docs/fail-closed-design.md; this is the first entry there.
#
# The registry is also read by `Sensor.degradations` whether or not any group is
# closed, so an operator who has NOT opted in can still see what degraded.

class AssetFault:
    """One asset that did not load as authored."""

    __slots__ = ("asset", "reason")

    def __init__(self, asset: str, reason: str):
        self.asset = asset
        self.reason = reason

    def __repr__(self) -> str:
        return f"AssetFault(asset={self.asset!r}, reason={self.reason!r})"

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, AssetFault)
            and (self.asset, self.reason) == (other.asset, other.reason)
        )

    def __hash__(self) -> int:
        return hash((self.asset, self.reason))


_ASSET_FAULTS: list = []


def record_asset_fault(asset: str, reason: str) -> None:
    """Record that ``asset`` did not load as authored. Never raises."""
    try:
        _ASSET_FAULTS.append(AssetFault(str(asset), str(reason)))
    except Exception:     # pragma: no cover - defensive: never raise at import
        pass


def asset_faults() -> list:
    """Every asset fault recorded since import, in the order they happened."""
    return list(_ASSET_FAULTS)


def clear_asset_faults() -> None:
    """Drop the registry. For tests; never called on the scan path."""
    _ASSET_FAULTS.clear()
