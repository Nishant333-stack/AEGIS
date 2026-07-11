"""Isolation Forest anomaly detector.

Uses scikit-learn's implementation when available (production path); otherwise
falls back to a compact, dependency-free NumPy implementation of the Liu-Ting-Zhou
isolation forest so the detector runs anywhere. Both expose the same
`fit` / `anomaly_score` API returning scores in [0, 1] (higher = more anomalous).
"""
from __future__ import annotations

import numpy as np


def _c(n: int) -> float:
    """Average path length of an unsuccessful BST search over n points."""
    if n <= 1:
        return 0.0
    return 2.0 * (np.log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n


class _Node:
    __slots__ = ("feature", "split", "left", "right", "size", "depth")

    def __init__(self):
        self.feature = -1
        self.split = 0.0
        self.left = None
        self.right = None
        self.size = 0
        self.depth = 0


class _NumpyIForest:
    def __init__(self, n_trees: int = 100, sample: int = 256, seed: int = 42):
        self.n_trees = n_trees
        self.sample = sample
        self.rng = np.random.default_rng(seed)
        self.trees: list[_Node] = []
        self._psi = sample

    def _build(self, X: np.ndarray, depth: int, max_depth: int) -> _Node:
        node = _Node()
        n = len(X)
        node.size = n
        node.depth = depth
        if depth >= max_depth or n <= 1:
            return node
        # random feature with non-zero range
        feats = self.rng.permutation(X.shape[1])
        for f in feats:
            cmin, cmax = X[:, f].min(), X[:, f].max()
            if cmax > cmin:
                node.feature = int(f)
                node.split = float(self.rng.uniform(cmin, cmax))
                mask = X[:, f] < node.split
                node.left = self._build(X[mask], depth + 1, max_depth)
                node.right = self._build(X[~mask], depth + 1, max_depth)
                return node
        return node  # all constant -> leaf

    def fit(self, X: np.ndarray) -> "_NumpyIForest":
        n = len(X)
        self._psi = min(self.sample, n)
        max_depth = int(np.ceil(np.log2(max(self._psi, 2))))
        self.trees = []
        for _ in range(self.n_trees):
            idx = self.rng.choice(n, size=self._psi, replace=False) if n > self._psi \
                else np.arange(n)
            self.trees.append(self._build(X[idx], 0, max_depth))
        return self

    def _path(self, x: np.ndarray, node: _Node) -> float:
        while node.feature != -1:
            node = node.left if x[node.feature] < node.split else node.right
        return node.depth + _c(node.size)

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        if not self.trees:
            return np.zeros(len(X))
        cpsi = _c(self._psi)
        out = np.empty(len(X))
        for i, x in enumerate(X):
            h = np.mean([self._path(x, t) for t in self.trees])
            out[i] = 2.0 ** (-h / cpsi) if cpsi > 0 else 0.0
        return out


class IsolationForestDetector:
    """Backend-agnostic Isolation Forest returning scores in [0, 1]."""

    def __init__(self, contamination: float = 0.03, n_estimators: int = 150,
                 seed: int = 42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.seed = seed
        self._impl = None
        self._backend = ""
        # calibration anchors learned from the training distribution so that a
        # *typical normal* window scores ~0 and a rare one ~1, regardless of
        # backend. Without this, iForest's raw ~0.5 baseline inflates everything.
        self._cal_lo = 0.0
        self._cal_hi = 1.0

    def _raw(self, X: np.ndarray) -> np.ndarray:
        if self._backend == "sklearn":
            return -self._impl.score_samples(X)   # higher = more anomalous
        return self._impl.anomaly_score(X)

    def fit(self, X: np.ndarray) -> "IsolationForestDetector":
        try:
            from sklearn.ensemble import IsolationForest
            m = IsolationForest(n_estimators=self.n_estimators,
                                contamination=self.contamination,
                                random_state=self.seed)
            m.fit(X)
            self._impl, self._backend = m, "sklearn"
        except Exception:
            m = _NumpyIForest(n_trees=self.n_estimators, seed=self.seed)
            m.fit(X)
            self._impl, self._backend = m, "numpy"
        raw = self._raw(X)
        self._cal_lo = float(np.median(raw))
        self._cal_hi = float(np.percentile(raw, 99))
        if self._cal_hi <= self._cal_lo:
            self._cal_hi = self._cal_lo + 1e-6
        return self

    @property
    def backend(self) -> str:
        return self._backend

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Per-row anomaly in [0,1], calibrated: normal≈0, rare≈1."""
        raw = self._raw(X)
        return np.clip((raw - self._cal_lo) / (self._cal_hi - self._cal_lo), 0, 1)
