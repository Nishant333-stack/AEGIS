"""Risk engine, risk-based access, and JIT maker-checker."""
import time

import pytest

from aegis.core.schema import (
    AccessDecision, Alert, AlertSeverity, EmploymentStatus, EventType, Role,
)
from aegis.crypto import AuditChain, get_provider
from aegis.pam.access import AccessPolicy, AccessRequest
from aegis.pam.jit import JITBroker, JITStatus
from aegis.risk.engine import RiskEngine


def _alert(sev):
    return Alert(user_id="U1", rule_id="R", title="t", severity=sev)


def test_context_risk_orders_by_privilege(sim):
    eng = RiskEngine()
    teller = sim.population.by_role(Role.TELLER)[0]
    admin = sim.population.by_role(Role.SYSADMIN)[0]
    assert eng.context_risk(admin) > eng.context_risk(teller)


def test_terminated_user_is_high_context_risk(sim):
    eng = RiskEngine()
    u = sim.population.by_role(Role.CONTRACTOR_DEV)[0]
    u.employment_status = EmploymentStatus.TERMINATED
    assert eng.context_risk(u) >= 45


def test_rules_risk_saturates():
    eng = RiskEngine()
    one = eng.rules_risk([_alert(AlertSeverity.CRITICAL)])
    many = eng.rules_risk([_alert(AlertSeverity.CRITICAL)] * 4)
    assert 0 < one <= many <= 100


def test_risk_decays_over_time(sim):
    eng = RiskEngine()
    u = sim.population.by_role(Role.DBA)[0]
    now = time.time()
    # snapshot the scalar — update() returns the same live RiskState object
    hot_score = eng.update(u, 90, [_alert(AlertSeverity.CRITICAL)], now=now).score
    # far in the future with no new signal → score decays below the spike
    cool_score = eng.update(u, 0, [], now=now + 48 * 3600).score
    assert cool_score < hot_score


def test_access_allows_low_risk(sim):
    pol = AccessPolicy()
    u = sim.population.by_role(Role.TELLER)[0]
    res = pol.decide(u, AccessRequest(u.user_id, EventType.CUSTOMER_PII_VIEW,
                                      risk_score=5))
    assert res.decision == AccessDecision.ALLOW


def test_access_denies_critical_risk(sim):
    pol = AccessPolicy()
    u = sim.population.by_role(Role.SYSADMIN)[0]
    res = pol.decide(u, AccessRequest(u.user_id, EventType.LOG_DELETE,
                                      risk_score=95))
    assert res.decision == AccessDecision.DENY_AND_ALERT


def test_access_steps_up_on_elevated(sim):
    pol = AccessPolicy()
    u = sim.population.by_role(Role.BRANCH_MANAGER)[0]
    res = pol.decide(u, AccessRequest(u.user_id, EventType.DB_QUERY,
                                      risk_score=50))
    assert res.step_up_required


def test_jit_maker_checker_blocks_self_approval():
    broker = JITBroker()
    req = broker.request("U1", "dba", "CORE.DB", "patch", risk=70)
    assert req.status == JITStatus.PENDING
    with pytest.raises(ValueError):
        broker.approve(req.request_id, approver="U1")
    broker.approve(req.request_id, approver="U2")
    assert broker.requests[req.request_id].status == JITStatus.APPROVED


def test_jit_low_risk_auto_approves():
    broker = JITBroker()
    req = broker.request("U1", "reader", "REPORTS", "routine", risk=10)
    assert req.status == JITStatus.APPROVED and req.auto_approved


def test_jit_expires_after_ttl():
    broker = JITBroker()
    req = broker.request("U1", "dba", "CORE.DB", "patch", risk=70, ttl_seconds=1)
    broker.approve(req.request_id, approver="U2")
    assert broker.is_active(req.request_id, now=time.time())
    assert not broker.is_active(req.request_id, now=time.time() + 10)


def test_jit_logs_to_audit_chain():
    ac = AuditChain(get_provider(force_backend="classical"))
    broker = JITBroker(audit=ac)
    req = broker.request("U1", "dba", "CORE.DB", "patch", risk=70)
    broker.approve(req.request_id, approver="U2")
    assert len(ac) >= 2 and ac.verify().valid
