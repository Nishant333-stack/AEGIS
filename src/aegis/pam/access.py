"""Risk-based access control (adaptive / step-up authentication).

Given a user's live risk score and the sensitivity of the action they are
attempting, decide in real time whether to:

  ALLOW               — low risk, proceed
  STEP_UP_MFA         — elevated risk, re-challenge identity
  REQUIRE_JIT_APPROVAL— high risk on a privileged action, route to maker-checker
  DENY_AND_ALERT      — critical risk, block and raise an incident

This is the enforcement point that turns detection into prevention, and it
implements least-privilege dynamically rather than as a static grant.
"""
from __future__ import annotations

from dataclasses import dataclass

from aegis.core.config import SETTINGS
from aegis.core.schema import (
    ACTION_SENSITIVITY, AccessDecision, EventType, User,
)


@dataclass
class AccessRequest:
    user_id: str
    action: EventType
    resource: str = ""
    risk_score: float = 0.0


@dataclass
class AccessResult:
    decision: AccessDecision
    reason: str
    effective_risk: float
    action_sensitivity: float
    step_up_required: bool = False

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "effective_risk": round(self.effective_risk, 1),
            "action_sensitivity": round(self.action_sensitivity, 2),
            "step_up_required": self.step_up_required,
        }


class AccessPolicy:
    """Maps (risk, action-sensitivity, identity) → an access decision."""

    def __init__(self):
        self.cfg = SETTINGS.risk

    def decide(self, user: User, req: AccessRequest) -> AccessResult:
        sensitivity = ACTION_SENSITIVITY.get(req.action, 0.3)
        # Sensitive actions raise the *effective* risk of the request, so the
        # bar to perform them scales with how damaging they'd be.
        effective = min(req.risk_score * (0.6 + 0.8 * sensitivity), 100)

        # Missing MFA is never acceptable for privileged actions.
        if not user.mfa_enrolled and sensitivity >= 0.5:
            return AccessResult(AccessDecision.STEP_UP_MFA,
                                "MFA not enrolled for a sensitive action",
                                effective, sensitivity, step_up_required=True)

        if effective >= self.cfg.deny_threshold:
            return AccessResult(AccessDecision.DENY_AND_ALERT,
                                f"Effective risk {effective:.0f} ≥ deny threshold",
                                effective, sensitivity)
        if effective >= self.cfg.jit_threshold and sensitivity >= 0.5:
            return AccessResult(AccessDecision.REQUIRE_JIT_APPROVAL,
                                "High-risk privileged action requires approval",
                                effective, sensitivity)
        if effective >= self.cfg.step_up_threshold:
            return AccessResult(AccessDecision.STEP_UP_MFA,
                                "Elevated risk — re-verify identity",
                                effective, sensitivity, step_up_required=True)
        return AccessResult(AccessDecision.ALLOW, "Within normal risk envelope",
                            effective, sensitivity)
