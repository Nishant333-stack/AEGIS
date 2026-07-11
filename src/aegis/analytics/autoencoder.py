"""Compact autoencoder for reconstruction-based anomaly detection.

A self-contained NumPy autoencoder (no TensorFlow/PyTorch needed) trained on
"normal" behavioral windows. At inference, a window that the network cannot
reconstruct well (high reconstruction error) is behaviorally novel — the core
signal for AI-driven insider-threat detection. Reconstruction error is
normalized against the training-error distribution so downstream scores are
comparable across users.

Architecture: standardize → encoder (d→h, tanh) → decoder (h→d) → MSE, trained
with mini-batch gradient descent and early-ish stopping. For very large
deployments this class can be swapped for a deeper Keras/PyTorch model behind
the same `fit`/`anomaly_score` interface.
"""
from __future__ import annotations

import numpy as np


class Autoencoder:
    def __init__(self, hidden: int = 8, epochs: int = 300, lr: float = 0.05,
                 seed: int = 42, anomaly_percentile: float = 97.5):
        self.hidden = hidden
        self.epochs = epochs
        self.lr = lr
        self.rng = np.random.default_rng(seed)
        self.anomaly_percentile = anomaly_percentile
        self._fitted = False

    # ---- standardization --------------------------------------------------
    def _standardize(self, X: np.ndarray) -> np.ndarray:
        return (X - self.mu) / self.sd

    # ---- training ---------------------------------------------------------
    def fit(self, X: np.ndarray) -> "Autoencoder":
        X = np.asarray(X, dtype=float)
        self.mu = X.mean(axis=0)
        self.sd = X.std(axis=0) + 1e-8
        Z = self._standardize(X)
        n, d = Z.shape
        h = min(self.hidden, max(2, d // 2))

        # Xavier init
        self.W1 = self.rng.normal(0, np.sqrt(1.0 / d), (d, h))
        self.b1 = np.zeros(h)
        self.W2 = self.rng.normal(0, np.sqrt(1.0 / h), (h, d))
        self.b2 = np.zeros(d)

        batch = min(64, n)
        for ep in range(self.epochs):
            idx = self.rng.permutation(n)
            for s in range(0, n, batch):
                b = idx[s:s + batch]
                xb = Z[b]
                # forward
                a1 = np.tanh(xb @ self.W1 + self.b1)
                out = a1 @ self.W2 + self.b2
                # backward (MSE)
                m = len(b)
                dout = 2 * (out - xb) / m
                dW2 = a1.T @ dout
                db2 = dout.sum(axis=0)
                da1 = (dout @ self.W2.T) * (1 - a1 ** 2)
                dW1 = xb.T @ da1
                db1 = da1.sum(axis=0)
                self.W2 -= self.lr * dW2
                self.b2 -= self.lr * db2
                self.W1 -= self.lr * dW1
                self.b1 -= self.lr * db1

        err = self._recon_error(Z)
        # Calibrate against the training-error distribution: a typical normal
        # window (median error) maps to ~0, a rare one (p99) to ~1.
        self.err_median = float(np.median(err))
        self.err_threshold = float(np.percentile(err, self.anomaly_percentile))
        self.err_p99 = float(np.percentile(err, 99))
        self.err_scale = max(self.err_p99 - self.err_median, 1e-8)
        self._fitted = True
        return self

    def _recon_error(self, Z: np.ndarray) -> np.ndarray:
        a1 = np.tanh(Z @ self.W1 + self.b1)
        out = a1 @ self.W2 + self.b2
        return np.mean((out - Z) ** 2, axis=1)

    # ---- inference --------------------------------------------------------
    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        return self._recon_error(self._standardize(np.asarray(X, dtype=float)))

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Per-row anomaly in [0,1], calibrated so normal≈0 and rare≈1."""
        err = self.reconstruction_error(X)
        return np.clip((err - self.err_median) / self.err_scale, 0, 1)

    def top_feature_errors(self, x: np.ndarray, k: int = 3) -> list[int]:
        """Indices of the features contributing most to reconstruction error."""
        z = self._standardize(np.asarray(x, dtype=float).reshape(1, -1))
        a1 = np.tanh(z @ self.W1 + self.b1)
        out = a1 @ self.W2 + self.b2
        per = (out - z) ** 2
        return list(np.argsort(per[0])[::-1][:k])
