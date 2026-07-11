# AEGIS — Insider Threat & Privileged Access Defense

**FinSpark Hackathon 2026 · Problem Statement 1 — Privileged Access Misuse & Insider Threat Detection**

AEGIS (*Adaptive Engine for Guarding Insider threats & Secure access*) is a
banking-grade platform that detects privileged-access misuse and insider
threats in real time using AI-driven behavioural analytics, enforces risk-based
access control over administrative systems, and protects sensitive credentials
and audit artefacts with **quantum-proof cryptography** (NIST ML-KEM / ML-DSA).

It ships as a single Python service: a REST API plus a live Security Operations
(SOC) dashboard you open in the browser, with one-click insider-threat scenario
injection for the demo.

---

## Why this matters

Insiders — employees, contractors, vendors, admins — already hold valid
credentials, so perimeter defences don't see them. RBI's cyber-security
framework mandates privileged-access management with session control,
least-privilege, and non-repudiable logging of privileged activity. AEGIS
implements exactly this, and adds quantum-safe protection so credentials and
audit logs stolen today cannot be decrypted by a future quantum computer
("harvest-now, decrypt-later").

---

## What it does (maps 1:1 to the problem statement)

| Expected outcome | How AEGIS delivers it |
|---|---|
| Detects misuse of privileged accounts | Rule engine + UEBA over privileged sessions, off-hours priv commands, unauthorised config changes |
| Identifies insider threats in real time | Streaming ingest → per-batch scoring → live dashboard & alerts |
| AI-driven behavioural analysis | Autoencoder + Isolation Forest + robust per-user & peer-group baselines (UEBA) |
| Risk-based access control | Composite risk drives ALLOW / STEP-UP MFA / JIT-approval / DENY at the enforcement point |
| Protects critical administrative systems | JIT privilege elevation with maker-checker, time-boxed grants, credential vault |
| Quantum-Proof Cryptography | ML-KEM-768 (FIPS 203) envelope-encrypted vault + ML-DSA-65 (FIPS 204) signed, hash-linked audit chain |

Focus areas covered: **Insider Threat Detection · Behaviour Analytics ·
Privileged Access Management · Risk-Based Authentication · Quantum-Safe
Security**.

---

## Quick start (uses `uv`)

```bash
# 1. install dependencies into an isolated environment
uv sync

# 2. verify the crypto + detection pipeline
uv run aegis selftest

# 3. run a headless end-to-end attack simulation
uv run aegis demo

# 4. launch the API + SOC dashboard
uv run aegis serve
#    → open http://127.0.0.1:8000
```

Optional production-grade PQC (Open Quantum Safe / liboqs):

```bash
uv sync --extra oqs      # auto-preferred when the liboqs native lib is present
```

No internet or dataset is required — a deterministic banking activity simulator
generates a realistic workforce and event stream, and the dashboard can inject
named insider-threat scenarios on demand. To run against the real **CMU CERT
r4.2** insider-threat corpus, see `docs/RESOURCES.md`.

### Run the tests

```bash
uv run pytest            # 40+ tests across crypto, UEBA, rules, PAM, API
```

---

## Live demo in 60 seconds

1. `uv run aegis serve` and open the dashboard.
2. Note the **quantum-safe posture** and **audit-chain integrity** badges (top right).
3. Click a scenario button — e.g. **data exfiltration** — and watch the target
   user jump up the **risk leaderboard** with MITRE-tagged alerts.
4. Click the user to see *why* they were flagged (behavioural drivers).
5. Approve/deny the **JIT elevation** request (maker-checker: the requester
   can't self-approve).
6. Every action is written to the **ML-DSA-signed audit chain** — try tampering
   with it in code and the integrity badge flips to `TAMPERED`.

A dependency-free `dashboard_preview.html` (baked demo data) is included so you
can see the console without starting the server.

---

## Architecture (one line)

```
log sources → normalize → UEBA (AE + iForest + baselines)
                        → MITRE rule engine
                        → composite risk (decay)
                        → risk-based access + JIT/PAM
                        → ML-DSA-signed audit chain   |  ML-KEM vault
```

See `docs/ARCHITECTURE.md` for the full design, `docs/RESOURCES.md` for datasets
/ standards / libraries, and `docs/DEMO_SCRIPT.md` for the pitch walkthrough.

---

## Project layout

```
src/aegis/
  core/        schema (events, users, enums), config
  data/        synthetic bank generator + CERT r4.2 loader
  crypto/      PQC provider (ML-KEM/ML-DSA + classical fallback), vault, audit chain
  analytics/   features, isolation forest, autoencoder, baselines, UEBA engine
  detection/   MITRE ATT&CK-mapped rules
  risk/        composite risk engine with decay
  pam/         risk-based access policy + JIT maker-checker broker
  api/         FastAPI server + self-contained SOC dashboard
  platform.py  orchestrator wiring it all together
  cli.py       `aegis serve | demo | selftest | pqc`
tests/         pytest suite
docs/          ARCHITECTURE, RESOURCES, DEMO_SCRIPT
```

## Security note

The pure-python ML-KEM/ML-DSA libraries are reference implementations (not
side-channel hardened) and are ideal for a prototype. For production, install
the `oqs` extra to route through the audited Open Quantum Safe library; AEGIS
auto-detects and prefers it. See `docs/ARCHITECTURE.md#cryptographic-posture`.
