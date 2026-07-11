"""MITRE-mapped rule engine coverage."""
from aegis.data.generator import SCENARIOS
from aegis.detection.rules import RuleEngine
from aegis.core.schema import Role


def _fire(sim, scenario, role):
    user = sim.population.by_role(role)[0]
    alerts = RuleEngine().evaluate(user, SCENARIOS[scenario](user))
    return {a.rule_id for a in alerts}, alerts


def test_usb_and_web_exfil_detected(sim):
    ids, alerts = _fire(sim, "data_exfiltration", Role.CONTRACTOR_DEV)
    assert "R003" in ids and "R004" in ids
    assert any(a.severity.value == "CRITICAL" for a in alerts)
    assert all(a.mitre_technique for a in alerts)


def test_privilege_escalation_detected(sim):
    ids, _ = _fire(sim, "privilege_escalation", Role.SYSADMIN)
    assert "R005" in ids or "R006" in ids


def test_log_tampering_detected(sim):
    ids, alerts = _fire(sim, "log_tampering", Role.SYSADMIN)
    assert "R007" in ids
    assert any("T1070" in a.mitre_technique for a in alerts)


def test_brute_force_and_impossible_travel(sim):
    ids, _ = _fire(sim, "compromised_credentials", Role.DBA)
    assert "R002" in ids and "R001" in ids


def test_normal_activity_low_false_positives(sim):
    eng = RuleEngine()
    total = 0
    for user in sim.population.users:
        evs = [e for e in sim.normal_stream(days=1) if e.user_id == user.user_id]
        total += len(eng.evaluate(user, evs))
    # A handful of benign rule hits across the whole org is acceptable; a storm
    # would indicate the rules are too trigger-happy.
    assert total <= 5, f"too many false positives: {total}"


def test_mitre_coverage_report():
    cov = RuleEngine().coverage
    tids = {c["technique"] for c in cov}
    assert {"T1070", "T1078", "T1110"}.issubset(tids)
    assert len(cov) >= 8
