"""Composite risk engine.

Fuses three signals into a single 0-100 user risk score:

  * behavior  — UEBA ensemble anomaly (autoencoder + iForest + baselines)
  * rules     — aggregated MITRE-mapped rule hits (severity-weighted)
  * context   — static identity risk (privilege level, watchlist, employment,
                MFA posture)

Risk is *stateful* and *decays*: a spike cools off over time (configurable
half-life) unless reinforced, mirroring how a SOC treats risk as a moving
signal rather than a one-shot verdict. This drives risk-based authentication:
the same action is allowed for a low-risk user and challenged/blocked for a
high-risk one.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

from aegis.core.config import SETTINGS
from aegis.core.schema import (
    Alert, AlertSeverity, EmploymentStatus, RiskTier, User, risk_tier,
)

_SEV_WEIGHT = {
    AlertSeverity.INFO: 0.05,
    AlertSeverity.LOW: 0.15,
    AlertSeverity.MEDIUM: 0.35,
    AlertSeverity.HIGH: 0.65,
    AlertSeverity.CRITICAL: 1.0,
}


@dataclass
class RiskState:
    user_id: str
    score: float = 0.0
    tier: RiskTier = RiskTier.LOW
    behavior: float = 0.0
    rules: float = 0.0
    context: float = 0.0
    last_update: float = field(default_factory=time.time)
    open_alerts: list[Alert] = field(default_factory=list)
    history: list[tuple[float, float]] = field(default_factory=list)  # (ts, score)

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "risk_score": round(self.score, 1),
            "tier": self.tier.value,
            "components": {
                "behavior": round(self.behavior, 1),
                "rules": round(self.rules, 1),
                "context": round(self.context, 1),
            },
            "open_alerts": len(self.open_alerts),
            "last_update": self.last_update,
        }


class RiskEngine:
    def __init__(self):
        self.cfg = SETTINGS.risk
        self.states: dict[str, RiskState] = {}

    # ---- context / identity risk -----------------------------------------
    def context_risk(self, user: User) -> float:
        r = 0.0
        r += {0: 0, 1: 5, 2: 10, 3: 20, 4: 30, 5: 40}.get(user.privilege_level, 10)
        if not user.mfa_enrolled:
            r += 20
        if user.on_watchlist:
            r += 25
        if user.employment_status == EmploymentStatus.NOTICE_PERIOD:
            r += 20
        elif user.employment_status == EmploymentStatus.TERMINATED:
            r += 45
        return float(min(r, 100))

    # ---- rule aggregation -------------------------------------------------
    @staticmethod
    def rules_risk(alerts: list[Alert]) -> float:
        if not alerts:
            return 0.0
        # Highest-severity alert dominates; additional alerts add diminishing weight.
        weights = sorted((_SEV_WEIGHT[a.severity] for a in alerts), reverse=True)
        agg = weights[0]
        for w in weights[1:]:
            agg = agg + w * (1 - agg) * 0.5   # saturating combination
        return float(min(agg * 100, 100))

    # ---- decay ------------------------------------------------------------
    def _decay(self, state: RiskState, now: float) -> float:
        dt = max(now - state.last_update, 0)
        factor = math.pow(0.5, dt / self.cfg.decay_half_life_s)
        return state.score * factor

    # ---- main update ------------------------------------------------------
    def update(self, user: User, behavior_score: float, alerts: list[Alert],
               now: float | None = None) -> RiskState:
        now = now or time.time()
        state = self.states.get(user.user_id) or RiskState(user_id=user.user_id)

        decayed = self._decay(state, now)
        behavior = float(behavior_score)
        rules = self.rules_risk(alerts)
        context = self.context_risk(user)

        instant = (self.cfg.w_behavior * behavior
                   + self.cfg.w_rules * rules
                   + self.cfg.w_context * context)
        # New risk is the max of (decayed prior, fresh instantaneous) so a spike
        # jumps immediately but memory of a recent spike lingers via decay.
        score = float(min(max(decayed, instant), 100))

        state.score = score
        state.behavior = behavior
        state.rules = rules
        state.context = context
        state.tier = risk_tier(score)
        state.last_update = now
        for a in alerts:
            a.risk_contribution = round(_SEV_WEIGHT[a.severity] * 100, 1)
        state.open_alerts = (state.open_alerts + alerts)[-50:]
        state.history.append((now, round(score, 1)))
        state.history = state.history[-200:]
        self.states[user.user_id] = state
        return state

    # ---- queries ----------------------------------------------------------
    def leaderboard(self, top: int = 20) -> list[RiskState]:
        return sorted(self.states.values(), key=lambda s: s.score, reverse=True)[:top]

    def get(self, user_id: str) -> RiskState | None:
        return self.states.get(user_id)
