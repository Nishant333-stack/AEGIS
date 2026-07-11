"""Just-In-Time (JIT) privilege elevation with maker-checker approval.

Standing privileged access is the single largest insider-risk surface. AEGIS
issues privilege on demand, time-boxed, and — for high-risk contexts — only
after a second authorized approver signs off (RBI 'maker-checker'). Every
state transition is written to the quantum-signed audit chain, so grants are
non-repudiable and expirations are provable.
"""
from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field


class JITStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass
class JITRequest:
    user_id: str
    role_requested: str
    resource: str
    justification: str
    risk_at_request: float
    request_id: str = field(default_factory=lambda: "JIT-" + uuid.uuid4().hex[:8])
    status: JITStatus = JITStatus.PENDING
    created_ts: float = field(default_factory=time.time)
    decided_ts: float | None = None
    approver: str = ""
    ttl_seconds: int = 3600
    expires_ts: float | None = None
    auto_approved: bool = False

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "user_id": self.user_id,
            "role_requested": self.role_requested,
            "resource": self.resource,
            "justification": self.justification,
            "risk_at_request": round(self.risk_at_request, 1),
            "status": self.status.value,
            "approver": self.approver,
            "auto_approved": self.auto_approved,
            "expires_in_s": (round(self.expires_ts - time.time())
                             if self.expires_ts else None),
        }


class JITBroker:
    """Manages the lifecycle of JIT elevation requests."""

    def __init__(self, audit=None, low_risk_auto_approve: float = 25.0):
        self.requests: dict[str, JITRequest] = {}
        self.audit = audit                       # optional AuditChain
        self.low_risk_auto_approve = low_risk_auto_approve

    def _log(self, actor: str, action: str, payload: dict) -> None:
        if self.audit is not None:
            self.audit.append(actor, action, payload)

    def request(self, user_id: str, role: str, resource: str, justification: str,
                risk: float, ttl_seconds: int = 3600) -> JITRequest:
        req = JITRequest(user_id=user_id, role_requested=role, resource=resource,
                         justification=justification, risk_at_request=risk,
                         ttl_seconds=ttl_seconds)
        # Low-risk, routine elevations can be auto-granted (time-boxed) to keep
        # operations smooth; anything above the bar needs a human approver.
        if risk <= self.low_risk_auto_approve:
            req.status = JITStatus.APPROVED
            req.auto_approved = True
            req.approver = "policy:auto"
            req.decided_ts = time.time()
            req.expires_ts = req.decided_ts + ttl_seconds
            self._log(user_id, "JIT_AUTO_APPROVED", req.to_dict())
        else:
            self._log(user_id, "JIT_REQUESTED", req.to_dict())
        self.requests[req.request_id] = req
        return req

    def approve(self, request_id: str, approver: str) -> JITRequest:
        req = self.requests[request_id]
        if req.user_id == approver:
            raise ValueError("maker-checker violation: requester cannot self-approve")
        if req.status != JITStatus.PENDING:
            return req
        req.status = JITStatus.APPROVED
        req.approver = approver
        req.decided_ts = time.time()
        req.expires_ts = req.decided_ts + req.ttl_seconds
        self._log(approver, "JIT_APPROVED", req.to_dict())
        return req

    def deny(self, request_id: str, approver: str, reason: str = "") -> JITRequest:
        req = self.requests[request_id]
        if req.status != JITStatus.PENDING:
            return req
        req.status = JITStatus.DENIED
        req.approver = approver
        req.decided_ts = time.time()
        self._log(approver, "JIT_DENIED", {**req.to_dict(), "reason": reason})
        return req

    def revoke(self, request_id: str, actor: str = "policy") -> JITRequest:
        req = self.requests[request_id]
        req.status = JITStatus.REVOKED
        self._log(actor, "JIT_REVOKED", req.to_dict())
        return req

    def is_active(self, request_id: str, now: float | None = None) -> bool:
        req = self.requests.get(request_id)
        if not req or req.status != JITStatus.APPROVED:
            return False
        now = now or time.time()
        if req.expires_ts and now >= req.expires_ts:
            req.status = JITStatus.EXPIRED
            self._log("policy", "JIT_EXPIRED", req.to_dict())
            return False
        return True

    def pending(self) -> list[JITRequest]:
        return [r for r in self.requests.values() if r.status == JITStatus.PENDING]

    def all(self) -> list[JITRequest]:
        return list(self.requests.values())
