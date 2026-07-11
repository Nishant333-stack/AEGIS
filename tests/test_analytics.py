"""UEBA analytics: features, detectors, and end-to-end separation."""
import time

import numpy as np

from aegis.analytics.autoencoder import Autoencoder
from aegis.analytics.engine import BehaviorEngine
from aegis.analytics.features import FEATURE_NAMES, featurize_window
from aegis.analytics.isolation_forest import IsolationForestDetector
from aegis.data.generator import SCENARIOS
from aegis.core.schema import Role


def test_feature_vector_shape_and_bounds(sim):
    events = sim.normal_stream(days=2)
    v = featurize_window(events[:50])
    assert v.shape == (len(FEATURE_NAMES),)
    assert v[2] <= 1.0 and v[13] <= 1.0        # ratios bounded in [0,1]


def test_empty_window_is_zero():
    assert np.all(featurize_window([]) == 0)


def test_isolation_forest_flags_outlier():
    rng = np.random.default_rng(0)
    X = rng.normal(0, 1, (300, 6))
    det = IsolationForestDetector(seed=0).fit(X)
    outlier = np.array([[12, 12, 12, 12, 12, 12]])
    assert det.anomaly_score(outlier)[0] > det.anomaly_score(X[:20]).mean()


def test_autoencoder_flags_novelty():
    rng = np.random.default_rng(0)
    X = rng.normal(0, 1, (300, 6))
    ae = Autoencoder(epochs=120, seed=0).fit(X)
    novel = np.array([[9, -9, 9, -9, 9, -9]])
    assert ae.anomaly_score(novel)[0] > ae.anomaly_score(X[:20]).mean()


def test_attacks_score_higher_than_normal(sim):
    base = time.time()
    eng = BehaviorEngine(seed=13).fit(
        sim.normal_stream(days=21, base_ts=base), sim.population.users)

    # normal baseline distribution
    normal = sim.normal_stream(days=1, base_ts=base)
    from collections import defaultdict
    by_user = defaultdict(list)
    for e in normal:
        by_user[e.user_id].append(e)
    normal_scores = [eng.score_window(u, evs).score for u, evs in by_user.items()]
    normal_p90 = np.percentile(normal_scores, 90)

    con = sim.population.by_role(Role.CONTRACTOR_DEV)[0]
    sa = sim.population.by_role(Role.SYSADMIN)[0]
    for name, user in [("data_exfiltration", con), ("privilege_escalation", sa),
                       ("log_tampering", sa)]:
        s = eng.score_window(user.user_id, SCENARIOS[name](user)).score
        assert s > normal_p90, f"{name} scored {s} <= normal p90 {normal_p90}"


def test_behavior_drivers_are_human_readable(sim):
    base = time.time()
    eng = BehaviorEngine(seed=13).fit(
        sim.normal_stream(days=21, base_ts=base), sim.population.users)
    con = sim.population.by_role(Role.CONTRACTOR_DEV)[0]
    bs = eng.score_window(con.user_id, SCENARIOS["data_exfiltration"](con))
    assert bs.drivers and all(isinstance(d, str) for d in bs.drivers)
    assert "1000000" not in " ".join(bs.drivers)   # no ugly uncapped sigmas
