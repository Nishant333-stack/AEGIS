"""Exercise the real post-quantum backends when they are installed.

These tests are skipped in environments without liboqs / kyber-py / dilithium-py
(e.g. an offline sandbox) and run in CI where the PQC dependencies are present,
proving the ML-KEM-768 / ML-DSA-65 tiers behave identically to the interface
verified by test_crypto.py.
"""
import importlib

import pytest

from aegis.crypto.pqc import PQCProvider, get_provider


def _have(mod: str) -> bool:
    try:
        importlib.import_module(mod)
        return True
    except Exception:
        return False


purepy = pytest.mark.skipif(
    not (_have("kyber_py.ml_kem") and _have("dilithium_py.ml_dsa")),
    reason="pure-python PQC libs not installed",
)
liboqs = pytest.mark.skipif(not _have("oqs"), reason="liboqs not installed")


@purepy
def test_purepy_mlkem_mldsa_roundtrip():
    prov = get_provider(force_backend="purepy", hybrid=False)
    assert prov.quantum_safe
    kp = prov.kem_keypair()
    ss, ct = prov.kem_encapsulate(kp.public)
    assert ss == prov.kem_decapsulate(kp.private, ct)
    sk = prov.sig_keypair()
    sig = prov.sign(sk.private, b"m")
    assert prov.verify(sk.public, b"m", sig)
    assert not prov.verify(sk.public, b"m2", sig)


@purepy
def test_hybrid_pqc_roundtrip():
    prov = get_provider(force_backend="purepy", hybrid=True)
    assert prov.hybrid
    kp = prov.kem_keypair()
    ss, ct = prov.kem_encapsulate(kp.public)
    assert ss == prov.kem_decapsulate(kp.private, ct)


@liboqs
def test_liboqs_roundtrip():
    prov = get_provider(force_backend="liboqs", hybrid=False)
    assert prov.quantum_safe
    kp = prov.kem_keypair()
    ss, ct = prov.kem_encapsulate(kp.public)
    assert ss == prov.kem_decapsulate(kp.private, ct)
