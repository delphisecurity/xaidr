"""EnforcementPolicy — the monitor/block decision as an object, not a string.

``enforcement_mode`` gates whether a block verdict actually blocks. Before this
module that gate was a string compared inline at six separate sites — five
asking ``== "block"`` (or ``!= "block"``) and one asking ``== "monitor"`` — plus
a seventh site, the constructor, validating against the literal tuple
``'monitor'``/``'block'``. Seven copies of a two-valued rule is seven places for
a new mode to be forgotten, and the failure mode is silent: an unrecognised
string compares unequal to ``"block"`` everywhere, so a typo or an unhandled
third mode does not raise, it quietly enforces nothing. A security control that
fails to a no-op when misconfigured is the one shape this codebase refuses (see
the ADV-2 note in ``privilege_tiers.py``).

So the rule lives here once, and the call sites ask it questions instead of
comparing strings. There are exactly two questions, and that is not an
accident — it is the claim this module makes about what a mode IS:

* ``enforces()`` — does a halting verdict actually halt in this mode? Every
  site that guarded an enforcement decision on ``== "block"`` asks this.
* ``downgrade(action)`` — what does this mode return in place of a halting
  action? Monitor softens; block is identity.

Anything a mode needs to decide that neither question expresses is a signal
that the seam is wrong, not that a third method is due.

Registration: ``resolve()`` is the ONLY string-to-object mapping, and it reads
``_POLICIES``. A distribution that needs a third mode adds it to that dict and
every one of the seven sites above follows, because none of them can see a name
any more. That is the whole point of routing them through one function.
"""

from __future__ import annotations


# The actions that HALT the agent. 'approval_required' belongs here with
# 'blocked' because an approval gate stops autonomous execution just as a block
# does — monitor mode's contract is that nothing is interrupted, not that
# nothing is labelled 'blocked'. Quarantine is deliberately absent: it is not a
# halt of the caller, and monitor has never softened it.
_HALTING_ACTIONS = frozenset({"blocked", "approval_required"})


class EnforcementPolicy:
    """One enforcement mode: its name, and what it does to a halting verdict.

    Open by construction — ``EnforcementPolicy("dry-run", enforces=False)`` is a
    valid policy today. What is closed is which NAMES a caller may spell, and
    that is ``resolve()``'s business, not this class's. The split matters: an
    embedding distribution can build policies freely, while a caller passing a
    string it read from a config file still gets the loud failure.
    """

    __slots__ = ("name", "_enforces")

    def __init__(self, name: str, enforces: bool):
        self.name = name
        self._enforces = enforces

    def enforces(self) -> bool:
        """True when a halting verdict actually halts under this policy.

        This is the question every ``== "block"`` site was really asking. It is
        about the MODE alone — whether a verdict is halting is the scanner's
        call, and is already decided by the time this is consulted.
        """
        return self._enforces

    def downgrade(self, action: str) -> str:
        """The action this policy returns in place of ``action``.

        Identity for an enforcing policy, and identity for any non-halting
        action under any policy — so this is safe to call unconditionally, and
        callers detect "did anything change?" by comparing the result rather
        than by re-testing the mode. Only a halting action under a
        non-enforcing policy moves, and it moves to 'flagged': observed,
        emitted, recorded, and not interrupted.
        """
        if self._enforces:
            return action
        return "flagged" if action in _HALTING_ACTIONS else action

    def __repr__(self) -> str:
        return f"EnforcementPolicy(name={self.name!r}, enforces={self._enforces!r})"


#: Observe-only. The default, and what ``shadow_mode`` collapses to.
MONITOR = EnforcementPolicy("monitor", enforces=False)

#: Enforcing. A block verdict blocks.
BLOCK = EnforcementPolicy("block", enforces=True)

# The name registry. `resolve()` reads this and nothing else reads it, so this
# dict is the single extension point for a new mode.
_POLICIES = {
    MONITOR.name: MONITOR,
    BLOCK.name: BLOCK,
}


def resolve(name_or_policy) -> EnforcementPolicy:
    """Map a mode name to its policy. Raises on anything else.

    Accepts an ``EnforcementPolicy`` unchanged so a caller that already holds
    one can pass it down without stringifying and re-parsing — that round trip
    is exactly how a policy an extension registered would get lost.

    The ValueError text is verbatim what ``DelphiSensor.__init__`` raised when
    it validated against a literal tuple. Keeping it identical is what makes
    this a refactor: ``tests/test_protect_manifest.py`` matches on
    ``"enforcement_mode"`` and ``autopatch`` re-raises it to the operator as
    the config-error message, so the wording is reachable by callers even
    though nothing asserts it character for character.
    """
    if isinstance(name_or_policy, EnforcementPolicy):
        return name_or_policy
    policy = _POLICIES.get(name_or_policy) if isinstance(name_or_policy, str) else None
    if policy is None:
        raise ValueError(
            f"enforcement_mode must be 'monitor' or 'block', got {name_or_policy!r}"
        )
    return policy
