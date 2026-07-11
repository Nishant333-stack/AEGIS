"""Privileged Access Management: risk-based access + JIT elevation."""
from aegis.pam.access import AccessPolicy, AccessRequest, AccessResult
from aegis.pam.jit import JITBroker, JITRequest, JITStatus

__all__ = [
    "AccessPolicy", "AccessRequest", "AccessResult",
    "JITBroker", "JITRequest", "JITStatus",
]
