"""Normalized event & entity schema (ECS-inspired).

Every log source (core banking, AD/LDAP, PAM gateway, DLP, VPN, DB audit)
is normalized into `Event` before entering the analytics pipeline, so the
platform is source-agnostic and horizontally extensible.

Implemented with stdlib dataclasses (zero third-party import) so the entire
detection core runs anywhere — the FastAPI layer adds pydantic on top only
for HTTP request validation.
"""
from __future__ import annotations

import enum
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


class EventType(str, enum.Enum):
    LOGIN = "LOGIN"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    VPN_CONNECT = "VPN_CONNECT"
    FILE_ACCESS = "FILE_ACCESS"
    FILE_COPY_USB = "FILE_COPY_USB"
    HTTP_UPLOAD = "HTTP_UPLOAD"
    EMAIL_EXTERNAL = "EMAIL_EXTERNAL"
    DB_QUERY = "DB_QUERY"
    PRIV_COMMAND = "PRIV_COMMAND"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    ACCOUNT_CREATE = "ACCOUNT_CREATE"
    ACCOUNT_PRIV_GRANT = "ACCOUNT_PRIV_GRANT"
    LOG_DELETE = "LOG_DELETE"
    PRIV_ESCALATION_ATTEMPT = "PRIV_ESCALATION_ATTEMPT"
    CUSTOMER_PII_VIEW = "CUSTOMER_PII_VIEW"
    JIT_REQUEST = "JIT_REQUEST"


class Role(str, enum.Enum):
    TELLER = "teller"
    BRANCH_MANAGER = "branch_manager"
    DBA = "dba"
    SYSADMIN = "sysadmin"
    NETWORK_ADMIN = "network_admin"
    AUDITOR = "auditor"
    CONTRACTOR_DEV = "contractor_dev"
    TREASURY_OPS = "treasury_ops"
    HR = "hr"


#: Roles that hold standing or eligible privileged access.
PRIVILEGED_ROLES = {Role.DBA, Role.SYSADMIN, Role.NETWORK_ADMIN, Role.CONTRACTOR_DEV}

#: Sensitivity weight of an action type used by the risk & policy engines.
ACTION_SENSITIVITY: dict[EventType, float] = {
    EventType.LOGIN: 0.10,
    EventType.LOGIN_FAILED: 0.15,
    EventType.LOGOUT: 0.00,
    EventType.VPN_CONNECT: 0.20,
    EventType.FILE_ACCESS: 0.25,
    EventType.FILE_COPY_USB: 0.80,
    EventType.HTTP_UPLOAD: 0.75,
    EventType.EMAIL_EXTERNAL: 0.50,
    EventType.DB_QUERY: 0.35,
    EventType.PRIV_COMMAND: 0.60,
    EventType.CONFIG_CHANGE: 0.70,
    EventType.ACCOUNT_CREATE: 0.85,
    EventType.ACCOUNT_PRIV_GRANT: 0.90,
    EventType.LOG_DELETE: 1.00,
    EventType.PRIV_ESCALATION_ATTEMPT: 0.95,
    EventType.CUSTOMER_PII_VIEW: 0.55,
    EventType.JIT_REQUEST: 0.30,
}


class EmploymentStatus(str, enum.Enum):
    ACTIVE = "active"
    NOTICE_PERIOD = "notice_period"
    TERMINATED = "terminated"


class AlertSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskTier(str, enum.Enum):
    LOW = "LOW"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AccessDecision(str, enum.Enum):
    ALLOW = "ALLOW"
    STEP_UP_MFA = "STEP_UP_MFA"
    REQUIRE_JIT_APPROVAL = "REQUIRE_JIT_APPROVAL"
    DENY_AND_ALERT = "DENY_AND_ALERT"


def _jsonable(v: Any) -> Any:
    if isinstance(v, enum.Enum):
        return v.value
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


@dataclass
class User:
    user_id: str
    name: str
    role: Role
    department: str
    privilege_level: int = 1          # 0=none … 5=domain admin
    mfa_enrolled: bool = True
    employment_status: EmploymentStatus = EmploymentStatus.ACTIVE
    on_watchlist: bool = False
    home_geo: str = "IN-MH-Mumbai"
    usual_hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {k: _jsonable(v) for k, v in asdict(self).items()}


@dataclass
class Event:
    user_id: str
    event_type: EventType
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    ts: float = field(default_factory=time.time)      # Unix epoch seconds
    host: str = "unknown"
    src_ip: str = "10.0.0.1"
    geo: str = "IN-MH-Mumbai"
    success: bool = True
    is_privileged_session: bool = False
    bytes_out: int = 0        # bytes moved (file/usb/upload/email)
    records: int = 0          # rows returned (db) / files touched
    target: str = ""          # file path / table / account / device
    command: str = ""         # for PRIV_COMMAND / CONFIG_CHANGE
    change_ticket: str = ""   # CAB ticket id, empty = unauthorized change
    detail: dict[str, Any] = field(default_factory=dict)

    def hour(self) -> int:
        return int(time.localtime(self.ts).tm_hour)

    def to_dict(self) -> dict[str, Any]:
        return {k: _jsonable(v) for k, v in asdict(self).items()}


@dataclass
class Alert:
    user_id: str
    rule_id: str
    title: str
    severity: AlertSeverity
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    risk_contribution: float = 0.0
    acknowledged: bool = False
    response_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: _jsonable(v) for k, v in asdict(self).items()}


def risk_tier(score: float) -> RiskTier:
    if score >= 80:
        return RiskTier.CRITICAL
    if score >= 60:
        return RiskTier.HIGH
    if score >= 40:
        return RiskTier.ELEVATED
    return RiskTier.LOW
