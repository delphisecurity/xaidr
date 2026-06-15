"""Action authorization — impact classification + local policy evaluation."""

from .classifier import classify
from .policy import AuthzDecision, build_request, evaluate, parse_action_policy

__all__ = ["classify", "AuthzDecision", "build_request", "evaluate", "parse_action_policy"]
