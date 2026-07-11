"""Quantum-Proof Cryptography (QPC) provider.

Exposes a uniform post-quantum KEM + signature interface backed by the best
primitive available on the host, degrading gracefully and *always reporting
its true security posture*:

  Tier 1  liboqs (Open Quantum Safe)   → production ML-KEM-768 / ML-DSA-65
  Tier 2  kyber-py + dilithium-py      → pure-python FIPS 203 / FIPS 204
  Tier 3  X25519 + Ed25519 (classical) → interoperable fallback, NOT quantum-safe

Design goals
------------
* One import path for the rest of the platform (`get_provider()`).
* `provider.quantum_safe` and `provider.report()` never lie — a SOC must know
  whether the artefacts it is protecting are actually harvest-now-decrypt-later
  resistant.
* Hybrid mode: when a PQC KEM is active we additionally mix in an X25519
  exchange (defense-in-depth, per NIST SP 800-227 / IETF hybrid drafts) so a
  break of *either* primitive alone does not expose the wrapped key.

The pure-python PQC libraries are reference implementations (not side-channel
hardened); Tier 1 (liboqs) is recommended for production and is auto-preferred
when installed. This is documented in ARCHITECTURE.md.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# --------------------------------------------------------------------------
# Backend interface
# --------------------------------------------------------------------------
class _Backend(Protocol):
    name: str
    kem_alg: str
    sig_alg: str
    quantum_safe: bool

    def kem_keygen(self) -> tuple[bytes, bytes]: ...
    def kem_encaps(self, ek: bytes) -> tuple[bytes, bytes]: ...
    def kem_decaps(self, dk: bytes, ct: bytes) -> bytes: ...
    def sig_keygen(self) -> tuple[bytes, bytes]: ...
    def sig_sign(self, sk: bytes, msg: bytes) -> bytes: ...
    def sig_verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool: ...


def _hkdf(shared: bytes, length: int = 32, info: bytes = b"aegis-qpc") -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
               info=info).derive(shared)


# --------------------------------------------------------------------------
# Tier 1: liboqs (Open Quantum Safe) — production grade
# --------------------------------------------------------------------------
class _OQSBackend:
    name = "liboqs"
    quantum_safe = True

    def __init__(self, kem_alg: str = "ML-KEM-768", sig_alg: str = "ML-DSA-65"):
        import oqs  # noqa: F401  (import-time capability probe)
        self._oqs = oqs
        self.kem_alg = kem_alg
        self.sig_alg = sig_alg

    def kem_keygen(self) -> tuple[bytes, bytes]:
        kem = self._oqs.KeyEncapsulation(self.kem_alg)
        ek = kem.generate_keypair()
        dk = kem.export_secret_key()
        return ek, dk

    def kem_encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        with self._oqs.KeyEncapsulation(self.kem_alg) as kem:
            ct, ss = kem.encap_secret(ek)
        return ss, ct

    def kem_decaps(self, dk: bytes, ct: bytes) -> bytes:
        kem = self._oqs.KeyEncapsulation(self.kem_alg, secret_key=dk)
        return kem.decap_secret(ct)

    def sig_keygen(self) -> tuple[bytes, bytes]:
        sig = self._oqs.Signature(self.sig_alg)
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        return pk, sk

    def sig_sign(self, sk: bytes, msg: bytes) -> bytes:
        return self._oqs.Signature(self.sig_alg, secret_key=sk).sign(msg)

    def sig_verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        with self._oqs.Signature(self.sig_alg) as v:
            return bool(v.verify(msg, sig, pk))


# --------------------------------------------------------------------------
# Tier 2: pure-python ML-KEM (kyber-py) + ML-DSA (dilithium-py)
# --------------------------------------------------------------------------
class _PurePyPQCBackend:
    name = "kyber-py+dilithium-py"
    quantum_safe = True
    kem_alg = "ML-KEM-768"
    sig_alg = "ML-DSA-65"

    def __init__(self):
        from dilithium_py.ml_dsa import ML_DSA_65
        from kyber_py.ml_kem import ML_KEM_768
        self._kem = ML_KEM_768
        self._sig = ML_DSA_65

    def kem_keygen(self) -> tuple[bytes, bytes]:
        ek, dk = self._kem.keygen()
        return ek, dk

    def kem_encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        key, ct = self._kem.encaps(ek)
        return key, ct

    def kem_decaps(self, dk: bytes, ct: bytes) -> bytes:
        return self._kem.decaps(dk, ct)

    def sig_keygen(self) -> tuple[bytes, bytes]:
        pk, sk = self._sig.keygen()
        return pk, sk

    def sig_sign(self, sk: bytes, msg: bytes) -> bytes:
        return self._sig.sign(sk, msg)

    def sig_verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            return bool(self._sig.verify(pk, msg, sig))
        except Exception:
            return False


# --------------------------------------------------------------------------
# Tier 3: classical X25519 + Ed25519 (interoperable, NOT quantum-safe)
# --------------------------------------------------------------------------
class _ClassicalBackend:
    name = "x25519+ed25519(classical)"
    quantum_safe = False
    kem_alg = "X25519-ECIES"
    sig_alg = "Ed25519"

    def kem_keygen(self) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat)
        sk = x25519.X25519PrivateKey.generate()
        dk = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ek = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return ek, dk

    def kem_encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat)
        peer = x25519.X25519PublicKey.from_public_bytes(ek)
        eph = x25519.X25519PrivateKey.generate()
        shared = eph.exchange(peer)
        ct = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return _hkdf(shared), ct

    def kem_decaps(self, dk: bytes, ct: bytes) -> bytes:
        sk = x25519.X25519PrivateKey.from_private_bytes(dk)
        eph_pub = x25519.X25519PublicKey.from_public_bytes(ct)
        return _hkdf(sk.exchange(eph_pub))

    def sig_keygen(self) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat)
        sk = ed25519.Ed25519PrivateKey.generate()
        skb = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pkb = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return pkb, skb

    def sig_sign(self, sk: bytes, msg: bytes) -> bytes:
        return ed25519.Ed25519PrivateKey.from_private_bytes(sk).sign(msg)

    def sig_verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
            return True
        except Exception:
            return False


# --------------------------------------------------------------------------
# Public provider
# --------------------------------------------------------------------------
@dataclass
class KeyPair:
    public: bytes
    private: bytes


class PQCProvider:
    """Facade over the selected backend, adding hybrid KEM + envelope helpers."""

    def __init__(self, backend: _Backend, hybrid: bool = True):
        self._b = backend
        # Hybrid only adds value when the primary KEM is post-quantum.
        self.hybrid = hybrid and backend.quantum_safe

    # ---- capability reporting --------------------------------------------
    @property
    def backend_name(self) -> str:
        return self._b.name

    @property
    def quantum_safe(self) -> bool:
        return self._b.quantum_safe

    @property
    def kem_alg(self) -> str:
        return self._b.kem_alg + ("+X25519(hybrid)" if self.hybrid else "")

    @property
    def sig_alg(self) -> str:
        return self._b.sig_alg

    def report(self) -> dict:
        return {
            "backend": self.backend_name,
            "kem_algorithm": self.kem_alg,
            "signature_algorithm": self.sig_alg,
            "quantum_safe": self.quantum_safe,
            "hybrid_mode": self.hybrid,
            "nist_standard": {
                "ML-KEM-768": "FIPS 203",
                "ML-DSA-65": "FIPS 204",
            } if self.quantum_safe else {},
            "posture": ("QUANTUM-SAFE" if self.quantum_safe
                        else "CLASSICAL-FALLBACK (install liboqs or kyber-py "
                             "for quantum resistance)"),
        }

    # ---- KEM --------------------------------------------------------------
    def kem_keypair(self) -> KeyPair:
        ek, dk = self._b.kem_keygen()
        if self.hybrid:
            x_ek, x_dk = _ClassicalBackend().kem_keygen()
            ek = _frame(ek) + _frame(x_ek)
            dk = _frame(dk) + _frame(x_dk)
        return KeyPair(ek, dk)

    def kem_encapsulate(self, ek: bytes) -> tuple[bytes, bytes]:
        """Return (shared_secret, ciphertext)."""
        if self.hybrid:
            pq_ek, x_ek = _unframe2(ek)
            k1, ct1 = self._b.kem_encaps(pq_ek)
            k2, ct2 = _ClassicalBackend().kem_encaps(x_ek)
            shared = _hkdf(k1 + k2, info=b"aegis-hybrid-kem")
            return shared, _frame(ct1) + _frame(ct2)
        return self._b.kem_encaps(ek)

    def kem_decapsulate(self, dk: bytes, ct: bytes) -> bytes:
        if self.hybrid:
            pq_dk, x_dk = _unframe2(dk)
            ct1, ct2 = _unframe2(ct)
            k1 = self._b.kem_decaps(pq_dk, ct1)
            k2 = _ClassicalBackend().kem_decaps(x_dk, ct2)
            return _hkdf(k1 + k2, info=b"aegis-hybrid-kem")
        return self._b.kem_decaps(dk, ct)

    # ---- signatures -------------------------------------------------------
    def sig_keypair(self) -> KeyPair:
        pk, sk = self._b.sig_keygen()
        return KeyPair(pk, sk)

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return self._b.sig_sign(sk, msg)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        return self._b.sig_verify(pk, msg, sig)

    @staticmethod
    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


# ---- length-prefixed framing for concatenated hybrid blobs ---------------
def _frame(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def _unframe2(blob: bytes) -> tuple[bytes, bytes]:
    n1 = int.from_bytes(blob[:4], "big")
    a = blob[4:4 + n1]
    rest = blob[4 + n1:]
    n2 = int.from_bytes(rest[:4], "big")
    b = rest[4:4 + n2]
    return a, b


_PROVIDER: PQCProvider | None = None


def get_provider(prefer_quantum_safe: bool = True, hybrid: bool = True,
                 force_backend: str | None = None) -> PQCProvider:
    """Return a process-wide provider, selecting the strongest backend available.

    force_backend ∈ {"liboqs", "purepy", "classical"} overrides auto-selection
    (used by tests to exercise a specific tier).
    """
    global _PROVIDER
    if _PROVIDER is not None and force_backend is None:
        return _PROVIDER

    order = []
    if force_backend == "liboqs":
        order = [_OQSBackend]
    elif force_backend == "purepy":
        order = [_PurePyPQCBackend]
    elif force_backend == "classical":
        order = [_ClassicalBackend]
    elif prefer_quantum_safe:
        order = [_OQSBackend, _PurePyPQCBackend, _ClassicalBackend]
    else:
        order = [_ClassicalBackend]

    last_err: Exception | None = None
    for cls in order:
        try:
            backend = cls()
            provider = PQCProvider(backend, hybrid=hybrid)
            if force_backend is None:
                _PROVIDER = provider
            return provider
        except Exception as e:  # backend unavailable -> try next tier
            last_err = e
            continue
    raise RuntimeError(f"No PQC backend available: {last_err}")


def _rand(n: int) -> bytes:
    return os.urandom(n)
