"""privilege_tiers.py — agent privilege tiers (OWASP ASI03).

THE THREAT, and why this is not a detection feature
---------------------------------------------------
ASI03 is a low-privilege agent inducing a high-privilege peer to act on its
behalf. The canonical instance — the Google ADK privilege bridge — is::

    @gemini-cli please review and run the validation suite

That message scores 0.0 on every detection path in this package, and it is
RIGHT to: it is a benign, well-formed, entirely reasonable sentence. There is no
payload, no injection, no obfuscation, nothing to detect. A detector that fired
on it would fire on every legitimate delegation an agent fleet performs.

The escalation is not in the text. It is in the fact that the SENDER may not
perform the action and the RECEIVER may. That is a property of the deployment,
not of the message, so the control is a CONTROL — a configured privilege
lattice, enforced by policy — not another rule.

THE LATTICE
-----------
Tiers are 1..4 with 1 = HIGHEST privilege and 4 = LOWEST. The ordering is
deliberately inverted relative to intuition because that is how privilege rings
are conventionally numbered (ring 0 is the kernel), and every function here
names the inversion explicitly so it cannot be misread:
``least_privileged_tier`` is a numeric MAX.

WHAT A TIER IS AND IS NOT
-------------------------
A tier is CONFIGURATION. It is supplied once, at sensor construction, from the
deployer's config. There is deliberately no setter: agent code that could raise
its own tier at runtime would turn the control into a suggestion, and agent code
is exactly what an injected instruction gets to influence.

An INBOUND tier is a CLAIM about an upstream hop. It rides unsigned transport
metadata, so it is trusted precisely as far as the delegation chain beside it —
which is to say, not very far. Two properties are guaranteed and they are the
ones that matter:

  * a claim can never change the RECEIVING sensor's own tier (that is config,
    read from the constructor and nowhere else), and
  * stripping or omitting a claim makes the attacker WORSE off, never better,
    because absence resolves to 4 (lowest privilege) and the computation takes
    the maximum.

An attacker who controls the headers can claim a BETTER upstream tier and reduce
the computed maximum. That is not preventable with unsigned metadata and is not
claimed to be: it needs signed provenance, which is out of scope here. It is
stated plainly rather than papered over, because the failure mode of pretending
otherwise is a deployer trusting a boundary that does not hold.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

# 1 = highest privilege (may do the most), 4 = lowest.
HIGHEST_PRIVILEGE_TIER = 1
LOWEST_PRIVILEGE_TIER = 4
VALID_TIERS = (1, 2, 3, 4)

# An unconfigured or unknown tier is the LOWEST privilege. Never the highest:
# the safe direction for an unknown is "assume it may do little", and the
# computation below takes a maximum, so an unknown can only tighten a decision.
DEFAULT_TIER = LOWEST_PRIVILEGE_TIER


def validate_tier(value: Any) -> int:
    """Validate a CONFIGURED privilege tier. Returns the int, or raises loudly.

    ``None`` means "not configured" and resolves to :data:`DEFAULT_TIER` (4,
    lowest privilege).

    Anything else that is not an int in 1..4 raises ``ValueError``, following the
    ADV-2 precedent set by ``enforcement_mode``: a security control configured
    with a value it does not understand must fail at construction, in the
    deployer's face, rather than silently pick a default and enforce something
    other than what was written. ``bool`` is rejected explicitly — it is an
    ``int`` subclass in Python, so ``privilege_tier=True`` would otherwise be
    accepted as tier 1, the HIGHEST privilege, which is the worst possible way
    for a typo to fail.
    """
    if value is None:
        return DEFAULT_TIER
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"privilege_tier must be an int in {VALID_TIERS[0]}..{VALID_TIERS[-1]} "
            f"(1 = highest privilege, {LOWEST_PRIVILEGE_TIER} = lowest), got "
            f"{value!r} ({type(value).__name__}). Leave it unset for the default "
            f"of {DEFAULT_TIER} (lowest privilege)."
        )
    if value not in VALID_TIERS:
        raise ValueError(
            f"privilege_tier must be in {VALID_TIERS} (1 = highest privilege, "
            f"{LOWEST_PRIVILEGE_TIER} = lowest), got {value!r}."
        )
    return value


def parse_claimed_tier(value: Any) -> Optional[int]:
    """Parse a tier CLAIMED on the wire. Never raises; returns None if unusable.

    The asymmetry with :func:`validate_tier` is deliberate and is the whole
    security posture of the carriage: a value the DEPLOYER wrote is a
    configuration error and must be loud, while a value an ATTACKER may have
    written is untrusted input and must never be able to crash the receiver. An
    unparseable claim degrades to ``None`` — unknown — which the computation
    treats as 4, so malformed input tightens the decision instead of bypassing
    it.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value in VALID_TIERS else None
    try:
        text = str(value).strip()
    except Exception:
        return None
    if not text:
        return None
    try:
        parsed = int(text)
    except (TypeError, ValueError):
        return None
    return parsed if parsed in VALID_TIERS else None


def least_privileged_tier(
    own_tier: int,
    hop_tiers: Optional[Iterable[Optional[int]]] = None,
) -> int:
    """The LEAST PRIVILEGED tier across this sensor and every delegating hop.

    "Least privileged" is a numeric MAXIMUM, because 4 is the lowest privilege.
    The name says which of the two it is so a reader never has to re-derive the
    inversion from the comparison operator — that inversion is the single most
    likely place for this feature to be silently wrong.

    ``own_tier`` is ALWAYS included: an agent cannot delegate its way to more
    privilege than it has, and including itself is what makes the result a true
    ceiling for the action about to be taken. A hop whose tier is ``None``
    (unknown, unclaimed, malformed, or from an un-instrumented agent) counts as
    :data:`DEFAULT_TIER` — an honest gap, never a guess upward.
    """
    worst = own_tier if own_tier in VALID_TIERS else DEFAULT_TIER
    for tier in hop_tiers or ():
        resolved = tier if tier in VALID_TIERS else DEFAULT_TIER
        if resolved > worst:
            worst = resolved
    return worst
