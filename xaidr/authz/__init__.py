"""Action authorization — impact classification + local policy evaluation."""

from .classifier import classify
from .policy import (
    AuthzDecision,
    PolicyVerdict,
    build_request,
    evaluate,
    explain_action_policy,
    parse_action_policy,
)

__all__ = [
    "classify", "AuthzDecision", "PolicyVerdict", "build_request", "evaluate",
    "explain_action_policy", "parse_action_policy",
]
