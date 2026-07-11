"""API smoke tests — skipped automatically if FastAPI isn't installed."""
import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from aegis.api.server import app
    return TestClient(app)


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "AEGIS" in r.text


def test_snapshot_and_pqc(client):
    assert client.get("/api/snapshot").status_code == 200
    assert "quantum_safe" in client.get("/api/pqc").json()


def test_scenario_injection_raises_risk(client):
    before = client.get("/api/snapshot").json()["leaderboard"]
    r = client.post("/api/scenario/data_exfiltration")
    assert r.status_code == 200
    assert r.json()["new_risk"] is not None


def test_audit_endpoint_reports_integrity(client):
    j = client.get("/api/audit").json()
    assert j["integrity_valid"] is True
