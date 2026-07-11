"""Tamper-evident, quantum-signed audit chain.

Every security-relevant action (alerts, access decisions, JIT approvals,
credential checkouts) is appended as a block that:

  1. Hash-links to its predecessor (SHA-256 over prev_hash||payload) — so any
     retroactive edit or deletion breaks every subsequent link, and
  2. Is signed with a PQC signature (ML-DSA / Dilithium, or Ed25519 fallback) —
     so an attacker who tampers *and* recomputes the hashes still cannot forge
     valid signatures without the private key.

This directly addresses the insider "cover your tracks" tactic (MITRE T1070,
Indicator Removal) and satisfies the RBI requirement for non-repudiable,
integrity-protected logging of privileged activity.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from aegis.crypto.pqc import PQCProvider, get_provider

_GENESIS = "0" * 64


@dataclass
class AuditBlock:
    index: int
    ts: float
    actor: str
    action: str
    payload: dict[str, Any]
    prev_hash: str
    block_hash: str
    signature: str  # hex

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index, "ts": self.ts, "actor": self.actor,
            "action": self.action, "payload": self.payload,
            "prev_hash": self.prev_hash, "block_hash": self.block_hash,
            "signature_preview": self.signature[:24] + "…",
        }


@dataclass
class VerifyResult:
    valid: bool
    length: int
    broken_at: int | None = None
    reason: str = ""


class AuditChain:
    """Append-only, hash-linked, PQC-signed ledger."""

    def __init__(self, provider: PQCProvider | None = None):
        self.provider = provider or get_provider()
        self._sig_kp = self.provider.sig_keypair()
        self._blocks: list[AuditBlock] = []

    @property
    def public_key(self) -> bytes:
        return self._sig_kp.public

    def _canonical(self, index: int, ts: float, actor: str, action: str,
                   payload: dict, prev_hash: str) -> bytes:
        return json.dumps(
            {"index": index, "ts": ts, "actor": actor, "action": action,
             "payload": payload, "prev_hash": prev_hash},
            sort_keys=True, separators=(",", ":")).encode()

    def append(self, actor: str, action: str, payload: dict) -> AuditBlock:
        index = len(self._blocks)
        prev_hash = self._blocks[-1].block_hash if self._blocks else _GENESIS
        ts = time.time()
        body = self._canonical(index, ts, actor, action, payload, prev_hash)
        block_hash = hashlib.sha256(body).hexdigest()
        signature = self.provider.sign(self._sig_kp.private, bytes.fromhex(block_hash))
        block = AuditBlock(index=index, ts=ts, actor=actor, action=action,
                           payload=payload, prev_hash=prev_hash,
                           block_hash=block_hash, signature=signature.hex())
        self._blocks.append(block)
        return block

    def verify(self) -> VerifyResult:
        """Walk the chain, checking every hash link and PQC signature."""
        prev_hash = _GENESIS
        for b in self._blocks:
            body = self._canonical(b.index, b.ts, b.actor, b.action,
                                   b.payload, b.prev_hash)
            recomputed = hashlib.sha256(body).hexdigest()
            if b.prev_hash != prev_hash:
                return VerifyResult(False, len(self._blocks), b.index,
                                    "prev_hash link mismatch")
            if recomputed != b.block_hash:
                return VerifyResult(False, len(self._blocks), b.index,
                                    "block hash mismatch (payload altered)")
            if not self.provider.verify(self._sig_kp.public,
                                        bytes.fromhex(b.block_hash),
                                        bytes.fromhex(b.signature)):
                return VerifyResult(False, len(self._blocks), b.index,
                                    "signature invalid (forged block)")
            prev_hash = b.block_hash
        return VerifyResult(True, len(self._blocks))

    def tail(self, n: int = 20) -> list[dict]:
        return [b.to_dict() for b in self._blocks[-n:]]

    def __len__(self) -> int:
        return len(self._blocks)
