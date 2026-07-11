"""Demo bootstrap: a pre-trained platform with live scenario injection.

Boots an `AegisPlatform`, trains it on 21 days of synthetic banking activity,
feeds one normal day so the SOC starts populated, and keeps the simulator handy
so the dashboard can inject named insider-threat scenarios on demand.
"""
from __future__ import annotations

import time

from aegis.core.schema import Role
from aegis.data.generator import BankSimulator, SCENARIOS
from aegis.platform import AegisPlatform

# Which role each scenario is injected onto (a realistic actor for the TTP).
_SCENARIO_ROLE = {
    "data_exfiltration": Role.CONTRACTOR_DEV,
    "privilege_escalation": Role.SYSADMIN,
    "compromised_credentials": Role.DBA,
    "log_tampering": Role.SYSADMIN,
    "dormant_then_burst": Role.CONTRACTOR_DEV,
}


class DemoEnvironment:
    def __init__(self, seed: int = 11):
        self.sim = BankSimulator(seed=seed)
        self.platform = AegisPlatform(seed=seed)
        self.base_ts = time.time()
        self._injected: list[str] = []

    def bootstrap(self) -> "DemoEnvironment":
        users = self.sim.population.users
        baseline = self.sim.normal_stream(days=21, base_ts=self.base_ts)
        self.platform.train(baseline, users)
        # one normal day so the leaderboard isn't empty
        self.platform.ingest(self.sim.normal_stream(days=1, base_ts=self.base_ts),
                             now=self.base_ts)
        return self

    def inject(self, scenario: str) -> dict:
        if scenario not in SCENARIOS:
            raise KeyError(scenario)
        role = _SCENARIO_ROLE.get(scenario, Role.SYSADMIN)
        target = self.sim.population.by_role(role)[0]
        events = SCENARIOS[scenario](target, now=time.time())
        states = self.platform.ingest(events, now=time.time())
        self._injected.append(scenario)
        st = self.platform.risk.get(target.user_id)
        return {
            "scenario": scenario,
            "target_user": target.user_id,
            "target_name": target.name,
            "role": role.value,
            "events_injected": len(events),
            "new_risk": round(st.score, 1) if st else None,
            "tier": st.tier.value if st else None,
        }

    def available_scenarios(self) -> list[str]:
        return list(SCENARIOS)


_ENV: DemoEnvironment | None = None


def get_env() -> DemoEnvironment:
    global _ENV
    if _ENV is None:
        _ENV = DemoEnvironment().bootstrap()
    return _ENV
