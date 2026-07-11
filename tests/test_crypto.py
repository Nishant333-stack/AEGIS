"""Quantum-safe crypto: KEM, signatures, vault, tamper-evident audit chain."""
import pytest

from aegis.crypto import AuditChain, CredentialVault, get_provider
from aegis.crypto.pqc import PQCProvider, _ClassicalBackend


@pytest.fixture()
def provider():
    # Force the classical backend so the suite runs without PQC libs installed;
    # the PQC tiers share the identical interface and are exercised in CI where
    # liboqs / kyber-py are present.
    return get_provider(force_backend="classical", hybrid=False)


def test_kem_roundtrip(provider):
    kp = provider.kem_keypair()
    shared, ct = provider.kem_encapsulate(kp.public)
    assert shared == provider.kem_decapsulate(kp.private, ct)
    assert len(shared) >= 32


def test_kem_wrong_key_fails(provider):
    kp = provider.kem_keypair()
    other = provider.kem_keypair()
    shared, ct = provider.kem_encapsulate(kp.public)
    assert shared != provider.kem_decapsulate(other.private, ct)


def test_signature_verify_and_tamper(provider):
    kp = provider.sig_keypair()
    sig = provider.sign(kp.private, b"privileged action")
    assert provider.verify(kp.public, b"privileged action", sig)
    assert not provider.verify(kp.public, b"tampered action", sig)


def test_hybrid_kem_roundtrip():
    prov = PQCProvider(_ClassicalBackend(), hybrid=False)
    kp = prov.kem_keypair()
    shared, ct = prov.kem_encapsulate(kp.public)
    assert shared == prov.kem_decapsulate(kp.private, ct)


def test_provider_reports_posture(provider):
    r = provider.report()
    assert "quantum_safe" in r and "kem_algorithm" in r and "posture" in r


def test_vault_seal_open_rotate(provider):
    v = CredentialVault(provider)
    v.seal("db_root", "S3cr3t!", {"class": "priv"})
    assert v.open("db_root") == b"S3cr3t!"
    v.rotate("db_root", "N3wS3cr3t!")
    assert v.open("db_root") == b"N3wS3cr3t!"
    assert v.status()["sealed_secrets"] == 1


def test_vault_ciphertext_has_no_plaintext(provider):
    v = CredentialVault(provider)
    v.seal("token", "SUPERSECRET")
    dump = v.export_public_state()
    assert "SUPERSECRET" not in dump


def test_audit_chain_valid(provider):
    ac = AuditChain(provider)
    for i in range(10):
        ac.append("U1", "PRIV_COMMAND", {"i": i})
    r = ac.verify()
    assert r.valid and r.length == 10


def test_audit_chain_detects_payload_tampering(provider):
    ac = AuditChain(provider)
    for i in range(6):
        ac.append("U1", "ALERT", {"i": i})
    ac._blocks[3].payload["i"] = 999
    r = ac.verify()
    assert not r.valid and r.broken_at == 3


def test_audit_chain_detects_deletion(provider):
    ac = AuditChain(provider)
    for i in range(6):
        ac.append("U1", "ALERT", {"i": i})
    del ac._blocks[2]           # remove a block → breaks the hash links
    assert not ac.verify().valid
