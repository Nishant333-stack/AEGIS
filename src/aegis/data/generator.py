"""Synthetic banking activity generator.

Produces a realistic population of employees and a stream of normalized
`Event`s that reflect day-to-day banking operations, then lets you inject
named insider-threat scenarios on top. Fully offline and deterministic
(seeded), so the demo is reproducible and needs no external dataset.

The behavioral "normal" is intentionally heterogeneous across roles and
individuals so the UEBA baselines have real structure to learn.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass

from aegis.core.schema import (
    EmploymentStatus,
    Event,
    EventType,
    PRIVILEGED_ROLES,
    Role,
    User,
)

_FIRST = ["Aarav", "Vivaan", "Aditya", "Diya", "Ananya", "Ishaan", "Kabir", "Sara",
          "Rohan", "Meera", "Arjun", "Nisha", "Karan", "Priya", "Devansh", "Riya",
          "Yash", "Tara", "Neel", "Zara", "Farhan", "Leela", "Omar", "Kavya"]
_LAST = ["Sharma", "Verma", "Iyer", "Nair", "Khan", "Reddy", "Gupta", "Bose",
         "Mehta", "Patel", "Rao", "Singh", "Das", "Kulkarni", "Menon", "Chopra"]

_DEPTS = {
    Role.TELLER: "Retail Banking",
    Role.BRANCH_MANAGER: "Retail Banking",
    Role.DBA: "IT Infrastructure",
    Role.SYSADMIN: "IT Infrastructure",
    Role.NETWORK_ADMIN: "IT Infrastructure",
    Role.AUDITOR: "Internal Audit",
    Role.CONTRACTOR_DEV: "Digital Engineering (Vendor)",
    Role.TREASURY_OPS: "Treasury",
    Role.HR: "Human Resources",
}

_PRIV_LEVEL = {
    Role.TELLER: 1, Role.BRANCH_MANAGER: 2, Role.AUDITOR: 2, Role.HR: 2,
    Role.TREASURY_OPS: 3, Role.CONTRACTOR_DEV: 3,
    Role.DBA: 4, Role.NETWORK_ADMIN: 4, Role.SYSADMIN: 5,
}

# Per-role "typical" daily action menu with rough weights.
_ROLE_ACTIONS: dict[Role, list[tuple[EventType, float]]] = {
    Role.TELLER: [(EventType.LOGIN, 2), (EventType.CUSTOMER_PII_VIEW, 30),
                  (EventType.DB_QUERY, 8), (EventType.FILE_ACCESS, 6)],
    Role.BRANCH_MANAGER: [(EventType.LOGIN, 2), (EventType.CUSTOMER_PII_VIEW, 12),
                          (EventType.DB_QUERY, 6), (EventType.EMAIL_EXTERNAL, 6),
                          (EventType.FILE_ACCESS, 10)],
    Role.DBA: [(EventType.LOGIN, 2), (EventType.DB_QUERY, 40),
               (EventType.PRIV_COMMAND, 14), (EventType.CONFIG_CHANGE, 4),
               (EventType.FILE_ACCESS, 8)],
    Role.SYSADMIN: [(EventType.LOGIN, 2), (EventType.PRIV_COMMAND, 30),
                    (EventType.CONFIG_CHANGE, 8), (EventType.FILE_ACCESS, 10),
                    (EventType.ACCOUNT_CREATE, 2)],
    Role.NETWORK_ADMIN: [(EventType.LOGIN, 2), (EventType.PRIV_COMMAND, 22),
                         (EventType.CONFIG_CHANGE, 10), (EventType.VPN_CONNECT, 6)],
    Role.AUDITOR: [(EventType.LOGIN, 2), (EventType.FILE_ACCESS, 22),
                   (EventType.DB_QUERY, 10), (EventType.CUSTOMER_PII_VIEW, 4)],
    Role.CONTRACTOR_DEV: [(EventType.LOGIN, 2), (EventType.VPN_CONNECT, 3),
                          (EventType.DB_QUERY, 18), (EventType.FILE_ACCESS, 14),
                          (EventType.PRIV_COMMAND, 6)],
    Role.TREASURY_OPS: [(EventType.LOGIN, 2), (EventType.DB_QUERY, 14),
                        (EventType.EMAIL_EXTERNAL, 8), (EventType.FILE_ACCESS, 10)],
    Role.HR: [(EventType.LOGIN, 2), (EventType.CUSTOMER_PII_VIEW, 6),
              (EventType.FILE_ACCESS, 16), (EventType.EMAIL_EXTERNAL, 6)],
}

_FILES = ["/fs/retail/accounts.csv", "/fs/loans/portfolio.xlsx",
          "/fs/treasury/positions.db", "/fs/hr/salary.xlsx",
          "/fs/audit/workpapers/", "/fs/kyc/customer_docs/",
          "/fs/core/gl_journal.dat", "/fs/cards/pan_vault.enc"]
_TABLES = ["CORE.ACCOUNTS", "CORE.TXN_LEDGER", "CARDS.PAN", "KYC.CUSTOMER",
           "LOANS.APPLICATIONS", "TREASURY.POSITIONS", "HR.PAYROLL"]
_PRIV_CMDS = ["sudo systemctl restart", "GRANT DBA TO", "net user /add",
              "chmod 777", "export DUMP", "iptables -F", "vault read secret/"]


@dataclass
class Population:
    users: list[User]

    def by_role(self, role: Role) -> list[User]:
        return [u for u in self.users if u.role == role]

    def get(self, user_id: str) -> User | None:
        return next((u for u in self.users if u.user_id == user_id), None)


class BankSimulator:
    """Deterministic generator of a bank's workforce and their activity."""

    def __init__(self, seed: int = 42, n_per_role: int | None = None):
        self.rnd = random.Random(seed)
        self.n_per_role = n_per_role or 4
        self.population = self._make_population()

    # ---- population -------------------------------------------------------
    def _make_population(self) -> Population:
        users: list[User] = []
        idx = 0
        for role in Role:
            count = self.n_per_role if role != Role.SYSADMIN else max(2, self.n_per_role - 1)
            for _ in range(count):
                idx += 1
                name = f"{self.rnd.choice(_FIRST)} {self.rnd.choice(_LAST)}"
                hosts = [f"WS-{role.value[:3].upper()}-{self.rnd.randint(100, 999)}"
                         for _ in range(self.rnd.randint(1, 2))]
                users.append(User(
                    user_id=f"U{idx:04d}",
                    name=name,
                    role=role,
                    department=_DEPTS[role],
                    privilege_level=_PRIV_LEVEL[role],
                    mfa_enrolled=self.rnd.random() > 0.05,
                    home_geo="IN-MH-Mumbai" if self.rnd.random() > 0.15 else "IN-KA-Bengaluru",
                    usual_hosts=hosts,
                ))
        return Population(users)

    # ---- normal activity --------------------------------------------------
    def _event_for(self, user: User, et: EventType, ts: float) -> Event:
        host = self.rnd.choice(user.usual_hosts) if user.usual_hosts else "WS-000"
        priv = user.role in PRIVILEGED_ROLES and et in {
            EventType.PRIV_COMMAND, EventType.CONFIG_CHANGE,
            EventType.ACCOUNT_CREATE, EventType.DB_QUERY}
        ev = Event(ts=ts, user_id=user.user_id, event_type=et, host=host,
                   geo=user.home_geo, is_privileged_session=priv,
                   src_ip=f"10.{self.rnd.randint(1,20)}.{self.rnd.randint(0,255)}.{self.rnd.randint(2,254)}")
        if et in {EventType.FILE_ACCESS, EventType.FILE_COPY_USB}:
            ev.target = self.rnd.choice(_FILES)
            ev.bytes_out = self.rnd.randint(2_000, 500_000)
            ev.records = self.rnd.randint(1, 200)
        elif et == EventType.DB_QUERY:
            ev.target = self.rnd.choice(_TABLES)
            ev.records = self.rnd.randint(1, 400)
        elif et == EventType.CUSTOMER_PII_VIEW:
            ev.target = self.rnd.choice(_TABLES[:4])
            ev.records = self.rnd.randint(1, 15)
        elif et in {EventType.PRIV_COMMAND, EventType.CONFIG_CHANGE}:
            ev.command = self.rnd.choice(_PRIV_CMDS)
            ev.change_ticket = f"CAB-{self.rnd.randint(10000, 99999)}" if self.rnd.random() > 0.1 else ""
        elif et == EventType.EMAIL_EXTERNAL:
            ev.bytes_out = self.rnd.randint(1_000, 80_000)
            ev.target = f"{self.rnd.choice(['partner','vendor','client'])}@ext.example.com"
        return ev

    def _business_ts(self, day: int, base: float) -> float:
        """A timestamp within business hours of `day` days before `base`."""
        hour = self.rnd.choices(range(8, 20),
                                weights=[3, 6, 8, 9, 7, 5, 8, 9, 8, 6, 4, 2])[0]
        minute = self.rnd.randint(0, 59)
        day_start = base - day * 86400
        lt = time.localtime(day_start)
        return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hour, minute,
                            0, 0, 0, -1))

    def normal_stream(self, days: int = 21, base_ts: float | None = None) -> list[Event]:
        """Generate `days` of baseline activity for the whole population."""
        base = base_ts if base_ts is not None else time.time()
        events: list[Event] = []
        for user in self.population.users:
            if user.employment_status == EmploymentStatus.TERMINATED:
                continue
            actions = _ROLE_ACTIONS[user.role]
            types = [a for a, _ in actions]
            weights = [w for _, w in actions]
            # per-user intensity multiplier → individual baselines differ
            intensity = self.rnd.uniform(0.7, 1.4)
            for day in range(days):
                if time.localtime(base - day * 86400).tm_wday >= 5:
                    continue  # weekend: skip most work
                n = max(1, int(self.rnd.gauss(sum(weights) * 0.35, 6) * intensity))
                # always one login to open the day
                events.append(self._event_for(user, EventType.LOGIN,
                                               self._business_ts(day, base)))
                for _ in range(n):
                    et = self.rnd.choices(types, weights=weights)[0]
                    events.append(self._event_for(user, et, self._business_ts(day, base)))
        events.sort(key=lambda e: e.ts)
        return events


# --------------------------------------------------------------------------
# Injectable insider-threat scenarios (each returns a burst of events "now").
# These mirror real CERT / MITRE insider patterns.
# --------------------------------------------------------------------------
def scenario_data_exfiltration(user: User, now: float | None = None) -> list[Event]:
    """Departing insider mass-downloads then exfiltrates via USB + upload.
    MITRE: Collection (T1005) + Exfiltration (T1052 / T1567)."""
    now = now or time.time()
    ev: list[Event] = []
    # after-hours login from unusual host
    ev.append(Event(ts=now, user_id=user.user_id, event_type=EventType.LOGIN,
                    host="WS-GUEST-666", geo=user.home_geo,
                    detail={"note": "after-hours"}))
    for i in range(14):
        ev.append(Event(ts=now + i * 20, user_id=user.user_id,
                        event_type=EventType.FILE_ACCESS,
                        target="/fs/cards/pan_vault.enc", bytes_out=4_000_000,
                        records=25_000, host="WS-GUEST-666"))
    ev.append(Event(ts=now + 320, user_id=user.user_id,
                    event_type=EventType.FILE_COPY_USB, target="USB:Kingston-8GB",
                    bytes_out=180_000_000, records=250_000, host="WS-GUEST-666"))
    ev.append(Event(ts=now + 360, user_id=user.user_id,
                    event_type=EventType.HTTP_UPLOAD, target="mega.nz",
                    bytes_out=140_000_000, host="WS-GUEST-666"))
    return ev


def scenario_privilege_escalation(user: User, now: float | None = None) -> list[Event]:
    """Sysadmin grants self extra rights, creates a backdoor account.
    MITRE: Privilege Escalation (T1078.003) + Persistence (T1136)."""
    now = now or time.time()
    return [
        Event(ts=now, user_id=user.user_id, event_type=EventType.PRIV_ESCALATION_ATTEMPT,
              command="GRANT DBA TO self", is_privileged_session=True, change_ticket=""),
        Event(ts=now + 30, user_id=user.user_id, event_type=EventType.ACCOUNT_CREATE,
              target="svc_backup_x", command="net user /add", is_privileged_session=True,
              change_ticket=""),
        Event(ts=now + 60, user_id=user.user_id, event_type=EventType.ACCOUNT_PRIV_GRANT,
              target="svc_backup_x", is_privileged_session=True, change_ticket=""),
        Event(ts=now + 90, user_id=user.user_id, event_type=EventType.CONFIG_CHANGE,
              command="iptables -F", is_privileged_session=True, change_ticket=""),
    ]


def scenario_compromised_credentials(user: User, now: float | None = None) -> list[Event]:
    """Account takeover: impossible-travel login + brute-force + off-hours DB dump.
    MITRE: Valid Accounts (T1078) + Brute Force (T1110)."""
    now = now or time.time()
    ev: list[Event] = []
    for i in range(9):
        ev.append(Event(ts=now + i * 3, user_id=user.user_id,
                        event_type=EventType.LOGIN_FAILED, success=False,
                        geo="RU-MOW-Moscow", src_ip="45.83.12.7"))
    ev.append(Event(ts=now + 40, user_id=user.user_id, event_type=EventType.LOGIN,
                    geo="RU-MOW-Moscow", src_ip="45.83.12.7",
                    detail={"impossible_travel": True}))
    ev.append(Event(ts=now + 70, user_id=user.user_id, event_type=EventType.DB_QUERY,
                    target="CORE.TXN_LEDGER", records=500_000, geo="RU-MOW-Moscow"))
    return ev


def scenario_log_tampering(user: User, now: float | None = None) -> list[Event]:
    """Insider deletes audit logs to cover tracks.
    MITRE: Defense Evasion — Indicator Removal (T1070)."""
    now = now or time.time()
    return [
        Event(ts=now, user_id=user.user_id, event_type=EventType.LOG_DELETE,
              target="/var/log/audit/audit.log", command="rm -f", is_privileged_session=True,
              change_ticket=""),
        Event(ts=now + 20, user_id=user.user_id, event_type=EventType.CONFIG_CHANGE,
              command="auditctl -D", is_privileged_session=True, change_ticket=""),
    ]


def scenario_dormant_then_burst(user: User, now: float | None = None) -> list[Event]:
    """Contractor near contract end: quiet, then sudden priv-command spike."""
    now = now or time.time()
    ev = []
    for i in range(25):
        ev.append(Event(ts=now + i * 5, user_id=user.user_id,
                        event_type=EventType.PRIV_COMMAND,
                        command="export DUMP", is_privileged_session=True,
                        records=20_000, change_ticket=""))
    return ev


SCENARIOS = {
    "data_exfiltration": scenario_data_exfiltration,
    "privilege_escalation": scenario_privilege_escalation,
    "compromised_credentials": scenario_compromised_credentials,
    "log_tampering": scenario_log_tampering,
    "dormant_then_burst": scenario_dormant_then_burst,
}
