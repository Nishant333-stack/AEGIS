"""Shared pytest fixtures."""
import time

import pytest

from aegis.data.generator import BankSimulator
from aegis.platform import AegisPlatform


@pytest.fixture(scope="session")
def sim():
    return BankSimulator(seed=13)


@pytest.fixture()
def trained_platform(sim):
    plat = AegisPlatform(seed=13)
    base = time.time()
    plat.train(sim.normal_stream(days=21, base_ts=base), sim.population.users)
    plat.ingest(sim.normal_stream(days=1, base_ts=base), now=base)
    return plat
