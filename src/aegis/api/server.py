"""AEGIS REST API + SOC dashboard (FastAPI).

Run:  uv run aegis serve         (or)  uv run uvicorn aegis.api.server:app --reload
Then open http://127.0.0.1:8000  for the live Security Operations dashboard.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from aegis.api.dashboard import DASHBOARD_HTML
from aegis.api.demo import get_env
from aegis.core.schema import EventType

app = FastAPI(
    title="AEGIS — Insider Threat & Privileged Access Defense",
    version="1.0.0",
    description="AI-driven UEBA + PAM + risk-based access with quantum-safe crypto.",
)


class ApproveBody(BaseModel):
    approver: str = "soc-analyst"
    reason: str = ""


class AuthorizeBody(BaseModel):
    user_id: str
    action: str = "PRIV_COMMAND"
    resource: str = ""


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return DASHBOARD_HTML


@app.get("/api/health")
def health() -> dict:
    env = get_env()
    return {"status": "ok", "trained": env.platform.state.trained,
            "quantum_safe": env.platform.provider.quantum_safe}


@app.get("/api/snapshot")
def snapshot() -> dict:
    return get_env().platform.snapshot()


@app.get("/api/pqc")
def pqc() -> dict:
    return get_env().platform.provider.report()


@app.get("/api/users/{user_id}")
def user_detail(user_id: str) -> dict:
    env = get_env()
    if user_id not in env.platform.users:
        raise HTTPException(404, "unknown user")
    user = env.platform.users[user_id]
    state = env.platform.risk.get(user_id)
    bscore = env.platform.score_behavior(user_id)
    return {
        "user": user.to_dict(),
        "risk": state.to_dict() if state else None,
        "behavior": bscore.to_dict(),
        "recent_alerts": [a.to_dict() for a in list(env.platform.state.alerts)
                          if a.user_id == user_id][:10],
    }


@app.get("/api/alerts")
def alerts(limit: int = 30) -> list[dict]:
    env = get_env()
    return [a.to_dict() for a in list(env.platform.state.alerts)[:limit]]


@app.get("/api/audit")
def audit(limit: int = 25) -> dict:
    env = get_env()
    v = env.platform.audit.verify()
    return {"length": len(env.platform.audit),
            "integrity_valid": v.valid, "broken_at": v.broken_at,
            "signature_algorithm": env.platform.provider.sig_alg,
            "blocks": env.platform.audit.tail(limit)}


@app.get("/api/vault")
def vault() -> dict:
    return get_env().platform.vault.status()


@app.get("/api/jit")
def jit_queue() -> dict:
    env = get_env()
    return {"pending": [r.to_dict() for r in env.platform.jit.pending()],
            "all": [r.to_dict() for r in env.platform.jit.all()[-25:]]}


@app.post("/api/jit/{request_id}/approve")
def jit_approve(request_id: str, body: ApproveBody) -> dict:
    env = get_env()
    try:
        return env.platform.jit.approve(request_id, body.approver).to_dict()
    except (KeyError, ValueError) as e:
        raise HTTPException(400, str(e))


@app.post("/api/jit/{request_id}/deny")
def jit_deny(request_id: str, body: ApproveBody) -> dict:
    env = get_env()
    try:
        return env.platform.jit.deny(request_id, body.approver, body.reason).to_dict()
    except KeyError as e:
        raise HTTPException(400, str(e))


@app.get("/api/scenarios")
def scenarios() -> list[str]:
    return get_env().available_scenarios()


@app.post("/api/scenario/{name}")
def inject_scenario(name: str) -> dict:
    env = get_env()
    try:
        return env.inject(name)
    except KeyError:
        raise HTTPException(404, f"unknown scenario '{name}'")


@app.post("/api/authorize")
def authorize(body: AuthorizeBody) -> dict:
    env = get_env()
    if body.user_id not in env.platform.users:
        raise HTTPException(404, "unknown user")
    try:
        action = EventType(body.action)
    except ValueError:
        raise HTTPException(400, f"unknown action '{body.action}'")
    return env.platform.authorize(body.user_id, action, body.resource).to_dict()
