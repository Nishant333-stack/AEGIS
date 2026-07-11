"""AEGIS command-line interface.

  uv run aegis serve       # start the API + SOC dashboard (http://127.0.0.1:8000)
  uv run aegis demo        # run a headless end-to-end attack simulation
  uv run aegis selftest    # verify crypto + detection pipeline
  uv run aegis pqc         # print quantum-safe posture
"""
from __future__ import annotations

import argparse
import sys


def _serve(args: argparse.Namespace) -> int:
    import uvicorn
    uvicorn.run("aegis.api.server:app", host=args.host, port=args.port,
                reload=args.reload)
    return 0


def _demo(args: argparse.Namespace) -> int:
    from aegis.api.demo import DemoEnvironment
    env = DemoEnvironment(seed=args.seed).bootstrap()
    print(f"Trained on {env.platform.state.events_ingested:,} baseline events; "
          f"{len(env.platform.users)} users monitored.")
    print(f"PQC posture: {env.platform.provider.report()['posture']}\n")
    for scn in env.available_scenarios():
        r = env.inject(scn)
        print(f"  ▶ {scn:24} → {r['target_name']:18} risk={r['new_risk']:>5} "
              f"[{r['tier']}]")
    print("\nTop risk after injections:")
    for s in env.platform.risk.leaderboard(top=5):
        u = env.platform.users[s.user_id]
        print(f"  {u.name:20} {u.role.value:15} {s.score:5.1f} {s.tier.value}")
    v = env.platform.audit.verify()
    print(f"\nAudit chain: {len(env.platform.audit)} blocks, "
          f"integrity={'VALID' if v.valid else 'BROKEN'}")
    return 0


def _selftest(args: argparse.Namespace) -> int:
    from aegis.crypto import AuditChain, CredentialVault, get_provider
    p = get_provider()
    kp = p.kem_keypair(); ss, ct = p.kem_encapsulate(kp.public)
    assert ss == p.kem_decapsulate(kp.private, ct), "KEM roundtrip failed"
    skp = p.sig_keypair(); sig = p.sign(skp.private, b"x")
    assert p.verify(skp.public, b"x", sig), "signature failed"
    v = CredentialVault(p); v.seal("k", "secret")
    assert v.open("k") == b"secret", "vault failed"
    ac = AuditChain(p); [ac.append("u", "a", {"i": i}) for i in range(3)]
    assert ac.verify().valid, "audit chain failed"
    print(f"selftest OK · backend={p.backend_name} · quantum_safe={p.quantum_safe}")
    return 0


def _pqc(args: argparse.Namespace) -> int:
    import json
    from aegis.crypto import get_provider
    print(json.dumps(get_provider().report(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aegis", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run API + dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--reload", action="store_true")
    s.set_defaults(fn=_serve)

    d = sub.add_parser("demo", help="headless attack simulation")
    d.add_argument("--seed", type=int, default=11)
    d.set_defaults(fn=_demo)

    t = sub.add_parser("selftest", help="verify crypto + pipeline")
    t.set_defaults(fn=_selftest)

    q = sub.add_parser("pqc", help="print quantum-safe posture")
    q.set_defaults(fn=_pqc)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
