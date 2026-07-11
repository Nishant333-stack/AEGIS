"""Data generator, CERT loader, and full-platform integration."""
import csv
import os
import time

from aegis.core.schema import EventType, Role
from aegis.data.cert_loader import load_r42
from aegis.data.generator import BankSimulator


def test_generator_is_deterministic():
    a = BankSimulator(seed=5).normal_stream(days=5, base_ts=1_700_000_000)
    b = BankSimulator(seed=5).normal_stream(days=5, base_ts=1_700_000_000)
    assert len(a) == len(b)
    assert [e.event_type for e in a[:50]] == [e.event_type for e in b[:50]]


def test_population_has_all_roles():
    sim = BankSimulator(seed=5)
    roles = {u.role for u in sim.population.users}
    assert roles == set(Role)


def test_cert_loader_parses_minimal_dir(tmp_path):
    d = tmp_path / "r42"
    d.mkdir()
    with open(d / "logon.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "date", "user", "pc", "activity"])
        w.writerow(["1", "01/02/2010 07:11:45", "AAM0658", "PC-1", "Logon"])
        w.writerow(["2", "01/02/2010 17:20:00", "AAM0658", "PC-1", "Logoff"])
    events = list(load_r42(str(d)))
    assert len(events) == 2
    assert events[0].event_type == EventType.LOGIN
    assert events[0].user_id == "AAM0658"


def test_platform_end_to_end_separation(trained_platform, sim):
    from aegis.data.generator import SCENARIOS
    plat = trained_platform
    con = sim.population.by_role(Role.CONTRACTOR_DEV)[0]
    sa = sim.population.by_role(Role.SYSADMIN)[0]
    plat.ingest(SCENARIOS["data_exfiltration"](con), now=time.time())
    plat.ingest(SCENARIOS["log_tampering"](sa), now=time.time())

    lb = plat.risk.leaderboard(top=3)
    top_ids = {s.user_id for s in lb}
    assert con.user_id in top_ids and sa.user_id in top_ids
    assert lb[0].score >= 60           # attackers surface as HIGH/CRITICAL

    # audit chain must remain intact through the whole run
    assert plat.audit.verify().valid


def test_platform_authorize_blocks_high_risk(trained_platform, sim):
    from aegis.data.generator import SCENARIOS
    plat = trained_platform
    sa = sim.population.by_role(Role.SYSADMIN)[0]
    plat.ingest(SCENARIOS["privilege_escalation"](sa), now=time.time())
    res = plat.authorize(sa.user_id, EventType.LOG_DELETE, "audit.log")
    assert res.decision.value in ("DENY_AND_ALERT", "REQUIRE_JIT_APPROVAL")


def test_snapshot_shape(trained_platform):
    snap = trained_platform.snapshot()
    for key in ("pqc", "leaderboard", "mitre_coverage", "audit_blocks"):
        assert key in snap
