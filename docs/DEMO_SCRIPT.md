# AEGIS — Demo Script (5–7 minutes)

A tight walkthrough for judges. Total runtime ~6 minutes with buffer for
questions.

## 0. Setup (before you present)

```bash
uv sync
uv run aegis serve
```

Open `http://127.0.0.1:8000`. If you can't run Python, open the included
`dashboard_preview.html` (baked demo data) instead.

## 1. Frame the problem (30s)

"Insiders — admins, contractors, vendors — already hold valid credentials, so
firewalls never see them. RBI mandates privileged-access management,
least-privilege, and non-repudiable logging. And a quantum computer will one day
decrypt anything stolen today. AEGIS solves all three: AI behavioural detection,
risk-based access control, and quantum-safe protection of credentials and
audit logs."

## 2. Orient on the console (45s)

Point to the two badges top-right: **quantum-safe posture** (KEM/signature
algorithms in use) and **audit-chain integrity** (`INTACT · N blocks`). Then the
KPI row — monitored users, events ingested, high/critical users, open alerts,
pending JIT, audit blocks. The **risk leaderboard** starts calm: everyone is
LOW because the platform learned each user's normal behaviour over 21 days.

## 3. Inject an insider attack (90s)

Click **data exfiltration**. Watch the target contractor jump to the top of the
leaderboard at HIGH risk. Two CRITICAL alerts appear in the feed, tagged
`T1052.001` (USB exfiltration) and `T1567` (web exfiltration).

Click the user row. The drawer explains *why*: behavioural drivers such as
"log max records: first-seen / far above own baseline" and the component
breakdown (autoencoder, isolation forest, self- and peer-deviation). This is the
AI behavioural analysis — not a static rule, but "this person is acting unlike
themselves and unlike their peers."

Inject **privilege escalation** and **audit-log tampering** too. Note the
sysadmin now shows `T1070` (indicator removal) — the classic cover-your-tracks
move.

## 4. Show enforcement — risk-based access (60s)

"Detection is only half the story; AEGIS acts." Explain the four possible
decisions (ALLOW / STEP-UP MFA / REQUIRE JIT APPROVAL / DENY-AND-ALERT). Because
the contractor is now HIGH risk, an attempt to run a privileged command is
denied and alerted, while a normal teller doing routine work is allowed. The
same action, different decision — driven by live risk. This is dynamic
least-privilege.

## 5. Show PAM — JIT with maker-checker (45s)

In the **JIT elevation queue**, a pending request needs a second approver. Point
out that the requester cannot self-approve (RBI maker-checker) — try it in code
and it raises. Approve it as the checker; the grant is time-boxed and expires
automatically. No standing admin rights anywhere.

## 6. The quantum-safe payoff (60s)

"Everything you just saw is sealed cryptographically." Two things:

- **Credential vault** — privileged secrets (core-banking DB root, SWIFT key,
  domain admin) are AES-256-GCM encrypted with the data key wrapped by
  **ML-KEM-768**. Steal the vault file and you get nothing, even with a future
  quantum computer.
- **Audit chain** — every alert, decision, and JIT grant is a hash-linked block
  signed with **ML-DSA-65**. The integrity badge proves it's intact. If an
  insider edits or deletes a log to hide their tracks, the chain breaks and the
  badge flips to `TAMPERED`.

Run `uv run pytest tests/test_crypto.py` live if time allows — the tamper-
detection tests pass in under a second.

## 7. Close (30s)

"AEGIS is a working, tested prototype: 40+ passing tests, MITRE-mapped, RBI-
aligned, quantum-safe, and it scales — the same pipeline runs on the real CMU
CERT dataset, and detection is horizontally partitionable per user. Every point
in Problem Statement 1 is addressed, end to end."

## One-liners for Q&A

- *False positives?* Rules are near-zero FP by design; ML is calibrated so
  normal sits near 0. Fusion + decay keeps the leaderboard clean (normal <20,
  attacks 69–79 on the demo).
- *Why not just rules?* Rules miss novel insider behaviour; the autoencoder
  catches "never seen this before." Why not just ML? ML alone has FPs and no
  TTP context. Fusing both is the point.
- *Is the pure-python PQC production-grade?* It's a reference implementation for
  the prototype; `uv sync --extra oqs` swaps in audited liboqs, and AEGIS auto-
  prefers it. Keys belong in an HSM/KMS in production.
- *Scale?* Stateless scoring per user, append-only audit chain, source-agnostic
  ingest. Add branches/systems by adding event feeds; partition users across
  workers.
