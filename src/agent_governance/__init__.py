"""Agent Governance Kit. A reference implementation, not a production boundary."""
from .policy import Intent, Policy, Decision, evaluate
from .gate import GovernanceGate, ApprovalIssuer, GovernanceError

__all__ = ["Intent", "Policy", "Decision", "evaluate", "GovernanceGate", "ApprovalIssuer", "GovernanceError"]
__version__ = "0.1.0"

