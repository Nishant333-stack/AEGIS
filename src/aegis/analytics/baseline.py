"""Robust per-user and peer-group behavioral baselines.

Complements the ML detectors with interpretable statistics:
* Per-user robust z-scores using median / MAD (resistant to the very outliers
  we're hunting), so "this user is acting unlike their own history" is explicit.
* Peer-group baselines (same role) so "this admin is acting unlike other admins"
  is captured even for a user with little personal history — the classic
  cold-start case in UEBA.
"""
from __future__ import annotations

import numpy as np

from aegis.analytics.features import FEATURE_NAMES

_MAD_SCALE = 1.4826  # makes MAD a consistent estimator of std for normal data


class RobustBaseline:
    """Median/MAD baseline over feature vectors for one entity (user or peer)."""

    def __init__(self, name: str = ""):
        self.name = name
        self.median = None
        self.mad = None
        self.n = 0

    #: Cap so a near-constant baseline feature (MAD→0) can't emit a giant z.
    Z_CAP = 50.0

    def fit(self, X: np.ndarray) -> "RobustBaseline":
        X = np.atleast_2d(np.asarray(X, dtype=float))
        self.n = len(X)
        self.median = np.median(X, axis=0)
        raw_mad = np.median(np.abs(X - self.median), axis=0) * _MAD_SCALE
        # Floor MAD relative to the feature's own spread so zero-variance
        # features don't explode; remember which features were ~constant.
        spread = (X.max(axis=0) - X.min(axis=0))
        floor = np.maximum(spread * 0.05, 0.5)
        self.mad = np.where(raw_mad < 1e-6, floor, raw_mad)
        self.near_constant = raw_mad < 1e-6
        return self

    def zscores(self, x: np.ndarray) -> np.ndarray:
        if self.median is None:
            return np.zeros(len(FEATURE_NAMES))
        z = (np.asarray(x, dtype=float) - self.median) / self.mad
        return np.clip(z, -self.Z_CAP, self.Z_CAP)

    def deviation(self, x: np.ndarray) -> float:
        """Bounded robust deviation in [0,1].

        Each feature's elevated z is squashed individually (z/(z+k)) so no
        single rare-but-benign action dominates; the result is their mean.
        """
        z = np.clip(self.zscores(x), 0, None)
        squashed = z / (z + 4.0)
        return float(np.mean(squashed))

    def top_deviations(self, x: np.ndarray, k: int = 3) -> list[tuple[str, float]]:
        z = self.zscores(x)
        order = np.argsort(z)[::-1][:k]
        out = []
        for i in order:
            if z[i] > 1.0:
                out.append((FEATURE_NAMES[i], round(float(z[i]), 1)))
        return out


class PeerGroupModel:
    """Holds a RobustBaseline per role for cold-start / relative anomaly."""

    def __init__(self):
        self.groups: dict[str, RobustBaseline] = {}

    def fit(self, role_to_matrix: dict[str, np.ndarray]) -> "PeerGroupModel":
        for role, X in role_to_matrix.items():
            if len(X) >= 3:
                self.groups[role] = RobustBaseline(role).fit(X)
        return self

    def deviation(self, role: str, x: np.ndarray) -> float:
        bl = self.groups.get(role)
        return bl.deviation(x) if bl else 0.0

    def top_deviations(self, role: str, x: np.ndarray, k: int = 3):
        bl = self.groups.get(role)
        return bl.top_deviations(x, k) if bl else []
