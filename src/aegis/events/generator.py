"""Backwards-compatibility alias.

The canonical event generator lives in :mod:`aegis.data.generator`. This module
re-exports it so older import paths (``aegis.events.generator``) keep working.
"""
from aegis.data.generator import *  # noqa: F401,F403
from aegis.data.generator import BankSimulator, Population, SCENARIOS  # noqa: F401
