"""MITRE-mapped detection rules.

Deterministic, explainable rules complement the ML/UEBA layer. Each rule
inspects a user's recent event window (plus identity context) and, if it fires,
emits an `Alert` carrying a severity, MITRE technique, and evidence. The rule
layer catches known-bad TTPs with near-zero false positives; the ML layer
catches the unknown-unknowns. Fusing both is what makes the composite risk both
sensitive and precise.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Callable

from aegis.core.config import SETTINGS
from aegis.core.schema import (
    Alert, AlertSeverity, EmploymentStatus, Event, EventType, User,
)
from aegis.detection.mitre import MITRE

# Known egress destinations for consumer file-sharing / paste sites.
_EXFIL_HOSTS = {"mega.nz", "dropbox.com", "wetransfer.com", "pastebin.com",
                "anonfiles.com", "drive.google.com", "0x0.st", "file.io"}

_SEV = AlertSeverity


@dataclass
class RuleContext:
    user: User
    events: list[Event]  # recent window for this user, time-ascending


RuleFn = Callable[[RuleContext], Alert | None]


def _mk(user_id: str, rule_id: str, title: str, sev: AlertSeverity,
        tech_key: str, evidence: dict, contribution: float) -> Alert:
    t = MITRE[tech_key]
    return Alert(user_id=user_id, rule_id=rule_id, title=title, severity=sev,
                 mitre_tactic=t.tactic, mitre_technique=f"{t.tid} {t.name}",
                 evidence=evidence, risk_contribution=contribution)


def _after_hours(ev: Event) -> bool:
    lo, hi = SETTINGS.business_hours
    return not (lo <= ev.hour() < hi)


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
def r_impossible_travel(ctx: RuleContext) -> Alert | None:
    home = ctx.user.home_geo.split("-")[0]
    for e in ctx.events:
        if e.event_type in (EventType.LOGIN, EventType.VPN_CONNECT):
            country = e.geo.split("-")[0]
            if country and country != home:
                return _mk(ctx.user.user_id, "R001",
                           f"Login from unusual country ({e.geo})", _SEV.HIGH,
                           "valid_accounts",
                           {"geo": e.geo, "home": ctx.user.home_geo, "src_ip": e.src_ip},
                           0.7)
    return None


def r_brute_force(ctx: RuleContext) -> Alert | None:
    fails = [e for e in ctx.events if e.event_type == EventType.LOGIN_FAILED]
    if len(fails) >= 5:
        return _mk(ctx.user.user_id, "R002",
                   f"{len(fails)} failed logins (possible brute force)",
                   _SEV.HIGH, "brute_force",
                   {"failed_attempts": len(fails), "src_ip": fails[-1].src_ip}, 0.6)
    return None


def r_usb_exfil(ctx: RuleContext) -> Alert | None:
    for e in ctx.events:
        if e.event_type == EventType.FILE_COPY_USB and (
                e.bytes_out >= 50_000_000 or e.records >= 10_000):
            return _mk(ctx.user.user_id, "R003",
                       f"Bulk copy to removable media ({e.bytes_out/1e6:.0f} MB)",
                       _SEV.CRITICAL, "exfil_usb",
                       {"device": e.target, "bytes": e.bytes_out, "records": e.records},
                       0.9)
    return None


def r_web_exfil(ctx: RuleContext) -> Alert | None:
    for e in ctx.events:
        if e.event_type == EventType.HTTP_UPLOAD:
            host = e.target.lower()
            if any(h in host for h in _EXFIL_HOSTS) or e.bytes_out >= 50_000_000:
                return _mk(ctx.user.user_id, "R004",
                           f"Large upload to external service ({e.target})",
                           _SEV.CRITICAL, "exfil_webservice",
                           {"destination": e.target, "bytes": e.bytes_out}, 0.85)
    return None


def r_priv_escalation(ctx: RuleContext) -> Alert | None:
    for e in ctx.events:
        if e.event_type == EventType.PRIV_ESCALATION_ATTEMPT or (
                "grant" in e.command.lower() and "self" in e.command.lower()):
            return _mk(ctx.user.user_id, "R005",
                       "Privilege escalation attempt (self-grant)", _SEV.CRITICAL,
                       "abuse_elevation",
                       {"command": e.command, "ticket": e.change_ticket or "NONE"}, 0.9)
    return None


def r_backdoor_account(ctx: RuleContext) -> Alert | None:
    created = [e for e in ctx.events if e.event_type == EventType.ACCOUNT_CREATE]
    granted = [e for e in ctx.events if e.event_type == EventType.ACCOUNT_PRIV_GRANT]
    if created and granted and any(not e.change_ticket for e in created + granted):
        return _mk(ctx.user.user_id, "R006",
                   "New privileged account created without change ticket",
                   _SEV.CRITICAL, "create_account",
                   {"accounts": [e.target for e in created]}, 0.85)
    return None


def r_log_tampering(ctx: RuleContext) -> Alert | None:
    for e in ctx.events:
        if e.event_type == EventType.LOG_DELETE or "auditctl -d" in e.command.lower():
            return _mk(ctx.user.user_id, "R007",
                       "Audit log deletion / tampering detected", _SEV.CRITICAL,
                       "indicator_removal",
                       {"target": e.target or e.command}, 0.95)
    return None


def r_unauth_config_change(ctx: RuleContext) -> Alert | None:
    risky = [e for e in ctx.events
             if e.event_type == EventType.CONFIG_CHANGE and not e.change_ticket]
    firewall = [e for e in risky if "iptables" in e.command.lower()
                or "firewall" in e.command.lower()]
    if firewall:
        return _mk(ctx.user.user_id, "R008",
                   "Firewall/defense change without approval", _SEV.HIGH,
                   "impair_defenses", {"command": firewall[0].command}, 0.7)
    if len(risky) >= 3:
        return _mk(ctx.user.user_id, "R008",
                   f"{len(risky)} unticketed config changes", _SEV.MEDIUM,
                   "impair_defenses", {"count": len(risky)}, 0.5)
    return None


def r_offhours_privileged(ctx: RuleContext) -> Alert | None:
    off = [e for e in ctx.events
           if e.is_privileged_session and _after_hours(e)
           and e.event_type in (EventType.PRIV_COMMAND, EventType.CONFIG_CHANGE,
                                EventType.DB_QUERY)]
    if len(off) >= 5:
        return _mk(ctx.user.user_id, "R009",
                   f"{len(off)} privileged actions outside business hours",
                   _SEV.MEDIUM, "valid_accounts", {"count": len(off)}, 0.45)
    return None


def r_bulk_db_pull(ctx: RuleContext) -> Alert | None:
    for e in ctx.events:
        if e.event_type in (EventType.DB_QUERY, EventType.CUSTOMER_PII_VIEW) \
                and e.records >= 100_000:
            return _mk(ctx.user.user_id, "R010",
                       f"Bulk record extraction ({e.records:,} rows from {e.target})",
                       _SEV.HIGH, "data_from_repo",
                       {"table": e.target, "records": e.records}, 0.75)
    return None


def r_terminated_access(ctx: RuleContext) -> Alert | None:
    if ctx.user.employment_status in (EmploymentStatus.TERMINATED,
                                      EmploymentStatus.NOTICE_PERIOD) and ctx.events:
        sev = _SEV.CRITICAL if ctx.user.employment_status == \
            EmploymentStatus.TERMINATED else _SEV.MEDIUM
        return _mk(ctx.user.user_id, "R011",
                   f"Activity from {ctx.user.employment_status.value} account",
                   sev, "valid_accounts",
                   {"status": ctx.user.employment_status.value,
                    "events": len(ctx.events)}, 0.6)
    return None


def r_unusual_host(ctx: RuleContext) -> Alert | None:
    if ctx.user.privilege_level < 3 or not ctx.user.usual_hosts:
        return None
    seen = Counter(e.host for e in ctx.events
                   if e.event_type in (EventType.LOGIN, EventType.PRIV_COMMAND))
    unknown = [h for h in seen if h not in ctx.user.usual_hosts and h != "unknown"]
    if unknown:
        return _mk(ctx.user.user_id, "R012",
                   f"Privileged use from unrecognized host ({unknown[0]})",
                   _SEV.MEDIUM, "remote_services",
                   {"hosts": unknown, "known": ctx.user.usual_hosts}, 0.4)
    return None


RULES: list[RuleFn] = [
    r_impossible_travel, r_brute_force, r_usb_exfil, r_web_exfil,
    r_priv_escalation, r_backdoor_account, r_log_tampering,
    r_unauth_config_change, r_offhours_privileged, r_bulk_db_pull,
    r_terminated_access, r_unusual_host,
]


class RuleEngine:
    def __init__(self, rules: list[RuleFn] | None = None):
        self.rules = rules or RULES

    def evaluate(self, user: User, events: list[Event]) -> list[Alert]:
        ctx = RuleContext(user=user, events=events)
        alerts = []
        for rule in self.rules:
            try:
                a = rule(ctx)
            except Exception:
                a = None
            if a is not None:
                alerts.append(a)
        return alerts

    @property
    def coverage(self) -> list[dict]:
        """MITRE techniques covered by the loaded rules (for reporting)."""
        seen = {}
        # Static mapping of rule → technique for the coverage report.
        rule_tech = {
            "R001": "valid_accounts", "R002": "brute_force", "R003": "exfil_usb",
            "R004": "exfil_webservice", "R005": "abuse_elevation",
            "R006": "create_account", "R007": "indicator_removal",
            "R008": "impair_defenses", "R009": "valid_accounts",
            "R010": "data_from_repo", "R011": "valid_accounts",
            "R012": "remote_services",
        }
        for rid, key in rule_tech.items():
            t = MITRE[key]
            seen[t.tid] = {"technique": t.tid, "name": t.name, "tactic": t.tactic}
        return sorted(seen.values(), key=lambda x: x["technique"])
