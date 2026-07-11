"""AEGIS platform orchestrator.

Wires the subsystems into one ingest→detect→score→decide→audit pipeline and
holds the live SOC state consumed by the API and dashboard:

  events → UEBA behavior score
         → MITRE rule alerts
         → composite risk (behavior + rules + context, with decay)
         → risk-based access decision + JIT routing
         → everything appended to the quantum-signed audit chain
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from aegis.analytics.engine import BehaviorEngine
from aegis.core.schema import Alert, Event, EventType, User
from aegis.crypto import AuditChain, CredentialVault, get_provider
from aegis.detection.rules import RuleEngine
from aegis.pam.access import AccessPolicy, AccessRequest, AccessResult
from aegis.pam.jit import JITBroker
from aegis.risk.engine import RiskEngine, RiskState


@dataclass
class PlatformState:
    trained: bool = False
    events_ingested: int = 0
    alerts: deque = field(default_factory=lambda: deque(maxlen=500))


class AegisPlatform:
    def __init__(self, seed: int = 42):
        self.provider = get_provider()
        self.behavior = BehaviorEngine(seed=seed)
        self.rules = RuleEngine()
        self.risk = RiskEngine()
        self.access = AccessPolicy()
        self.audit = AuditChain(self.provider)
        self.vault = CredentialVault(self.provider)
        self.jit = JITBroker(audit=self.audit)
        self.users: dict[str, User] = {}
        self.recent: dict[str, deque] = defaultdict(lambda: deque(maxlen=400))
        self.state = PlatformState()
        self._seed_vault()

    # ---- setup ------------------------------------------------------------
    def _seed_vault(self) -> None:
        for name, secret in {
            "core_banking_db_root": "R00t-CB!-2026",
            "swift_gateway_key": "swift-a1b2c3d4",
            "ad_domain_admin": "P@ssw0rd-DA",
            "hsm_pin": "8842-1190-5567",
        }.items():
            self.vault.seal(name, secret, {"class": "privileged-credential"})

    def register_users(self, users: list[User]) -> None:
        for u in users:
            self.users[u.user_id] = u

    def train(self, baseline_events: list[Event], users: list[User]) -> None:
        self.register_users(users)
        self.behavior.fit(baseline_events, users)
        self.audit.append("system", "BASELINE_TRAINED",
                          {"users": len(users), "events": len(baseline_events),
                           "iforest_backend": self.behavior.iforest_backend})
        self.state.trained = True

    # ---- live ingest ------------------------------------------------------
    def ingest(self, events: list[Event], now: float | None = None
               ) -> list[RiskState]:
        """Process a batch of events; return the risk states that changed."""
        now = now or time.time()
        by_user: dict[str, list[Event]] = defaultdict(list)
        for e in events:
            self.recent[e.user_id].append(e)
            by_user[e.user_id].append(e)
            self.state.events_ingested += 1

        changed: list[RiskState] = []
        for uid, evs in by_user.items():
            user = self.users.get(uid)
            if user is None:
                continue
            window = list(self.recent[uid])
            bscore = self.behavior.score_window(uid, window).score
            alerts = self.rules.evaluate(user, window)
            state = self.risk.update(user, bscore, alerts, now=now)
            for a in alerts:
                self.state.alerts.appendleft(a)
                self.audit.append(uid, "ALERT", {
                    "rule": a.rule_id, "title": a.title,
                    "severity": a.severity.value, "mitre": a.mitre_technique})
            changed.append(state)
        return changed

    # ---- enforcement ------------------------------------------------------
    def authorize(self, user_id: str, action: EventType, resource: str = ""
                  ) -> AccessResult:
        user = self.users[user_id]
        state = self.risk.get(user_id)
        risk = state.score if state else self.risk.context_risk(user)
        res = self.access.decide(user, AccessRequest(user_id, action, resource, risk))
        self.audit.append(user_id, "ACCESS_DECISION", {
            "action": action.value, "resource": resource,
            "decision": res.decision.value, "effective_risk": res.effective_risk})
        return res

    # ---- reporting --------------------------------------------------------
    def score_behavior(self, user_id: str):
        return self.behavior.score_window(user_id, list(self.recent[user_id]))

    def snapshot(self) -> dict:
        lb = self.risk.leaderboard(top=25)
        return {
            "trained": self.state.trained,
            "events_ingested": self.state.events_ingested,
            "monitored_users": len(self.users),
            "open_alerts": len(self.state.alerts),
            "pending_jit": len(self.jit.pending()),
            "pqc": self.provider.report(),
            "audit_blocks": len(self.audit),
            "leaderboard": [
                {**s.to_dict(), "name": self.users[s.user_id].name
                 if s.user_id in self.users else s.user_id,
                 "role": self.users[s.user_id].role.value
                 if s.user_id in self.users else "?"}
                for s in lb
            ],
            "mitre_coverage": self.rules.coverage,
        }
