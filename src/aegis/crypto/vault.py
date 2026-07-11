"""Quantum-safe credential vault.

Privileged secrets (DB passwords, SSH keys, service-account tokens) are sealed
with AES-256-GCM. The AES data-encryption key is never stored: it is wrapped
using the PQC KEM (`envelope encryption`), so an attacker who exfiltrates the
vault file gains nothing without the PQC decapsulation key — and, because the
KEM is ML-KEM (or hybrid), the wrapped key is resistant to
harvest-now-decrypt-later quantum attacks.

Each secret is individually sealed, supports rotation, and records an access
count so the PAM layer can enforce one-time / time-boxed credential checkout.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aegis.crypto.pqc import PQCProvider, get_provider


@dataclass
class SealedSecret:
    name: str
    kem_ciphertext: bytes   # wrapped AES key (PQC KEM output)
    nonce: bytes
    ciphertext: bytes       # AES-256-GCM(secret)
    created_ts: float
    rotated_ts: float
    access_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class CredentialVault:
    """Envelope-encrypted secret store keyed by a PQC KEM keypair."""

    def __init__(self, provider: PQCProvider | None = None):
        self.provider = provider or get_provider()
        self._kp = self.provider.kem_keypair()   # vault master KEM keypair
        self._store: dict[str, SealedSecret] = {}

    # ---- lifecycle --------------------------------------------------------
    def seal(self, name: str, secret: str | bytes,
             metadata: dict | None = None) -> SealedSecret:
        """Encrypt and store a secret under `name`."""
        data = secret.encode() if isinstance(secret, str) else secret
        shared, kem_ct = self.provider.kem_encapsulate(self._kp.public)
        aes_key = shared[:32]
        nonce = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(nonce, data, name.encode())
        now = time.time()
        sealed = SealedSecret(name=name, kem_ciphertext=kem_ct, nonce=nonce,
                              ciphertext=ct, created_ts=now, rotated_ts=now,
                              metadata=metadata or {})
        self._store[name] = sealed
        return sealed

    def open(self, name: str) -> bytes:
        """Decrypt and return a secret; increments access count (auditable)."""
        s = self._store[name]
        shared = self.provider.kem_decapsulate(self._kp.private, s.kem_ciphertext)
        aes_key = shared[:32]
        plain = AESGCM(aes_key).decrypt(s.nonce, s.ciphertext, name.encode())
        s.access_count += 1
        return plain

    def rotate(self, name: str, new_secret: str | bytes) -> SealedSecret:
        meta = self._store[name].metadata if name in self._store else {}
        sealed = self.seal(name, new_secret, meta)
        sealed.rotated_ts = time.time()
        return sealed

    def names(self) -> list[str]:
        return sorted(self._store)

    def status(self) -> dict[str, Any]:
        return {
            "sealed_secrets": len(self._store),
            "kem_backend": self.provider.backend_name,
            "quantum_safe": self.provider.quantum_safe,
            "secrets": [
                {"name": s.name, "access_count": s.access_count,
                 "age_hours": round((time.time() - s.rotated_ts) / 3600, 2)}
                for s in self._store.values()
            ],
        }

    # ---- persistence (ciphertext only; keys stay in HSM/KMS in prod) ------
    def export_public_state(self) -> str:
        """Serialize sealed blobs (no plaintext, no private key) for backup."""
        return json.dumps({
            "backend": self.provider.backend_name,
            "quantum_safe": self.provider.quantum_safe,
            "secrets": {
                name: {
                    "kem_ciphertext": s.kem_ciphertext.hex(),
                    "nonce": s.nonce.hex(),
                    "ciphertext": s.ciphertext.hex(),
                    "created_ts": s.created_ts,
                    "access_count": s.access_count,
                }
                for name, s in self._store.items()
            },
        }, indent=2)
