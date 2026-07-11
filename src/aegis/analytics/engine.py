"""Behavioral analytics engine — orchestrates the UEBA ensemble.

Training (on a window of "normal" activity):
  * per-user robust baselines (median/MAD)
  * per-role peer-group baselines
  * a global Isolation Forest over all windows
  * a global autoencoder over all windows

Scoring (a new activity window):
  behavior_score ∈ [0,1] = weighted fusion of
     - autoencoder reconstruction anomaly
     - isolation-forest anomaly
     - user's own robust deviation
     - peer-group relative deviation
  plus a human-readable explanation of the top contributing features.

The fusion is deliberately transparent (weights, not a black box) so SOC
analysts can trust and tune it — important for adoption in regulated banking.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from aegis.analytics.autoencoder import Autoencoder
from aegis.analytics.baseline import PeerGroupModel, RobustBaseline
from aegis.analytics.features import (
    FEATURE_NAMES, featurize_window, window_events,
)
from aegis.analytics.isolation_forest import IsolationForestDetector
from aegis.core.config import SETTINGS
from aegis.core.schema import Event, User


@dataclass
class BehaviorScore:
    user_id: str
    score: float                       # fused behavioral anomaly, 0-100
    ae_anomaly: float = 0.0
    iforest_anomaly: float = 0.0
    self_deviation: float = 0.0
    peer_deviation: float = 0.0
    drivers: list[str] = field(default_factory=list)   # human-readable reasons
    feature_vector: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "behavior_score": round(self.score, 1),
            "components": {
                "autoencoder": round(self.ae_anomaly, 3),
                "isolation_forest": round(self.iforest_anomaly, 3),
                "self_deviation": round(self.self_deviation, 3),
                "peer_deviation": round(self.peer_deviation, 3),
            },
            "drivers": self.drivers,
        }


class BehaviorEngine:
    def __init__(self, seed: int | None = None):
        cfg = SETTINGS.model
        self.seed = seed if seed is not None else cfg.random_state
        self.iforest = IsolationForestDetector(
            contamination=cfg.contamination, seed=self.seed)
        self.autoenc = Autoencoder(
            epochs=cfg.ae_epochs * 6, seed=self.seed,
            anomaly_percentile=cfg.ae_anomaly_percentile)
        self.user_baselines: dict[str, RobustBaseline] = {}
        self.peer_model = PeerGroupModel()
        self.user_roles: dict[str, str] = {}
        self.user_home: dict[str, str] = {}
        self._fitted = False

    # ---- training ---------------------------------------------------------
    def fit(self, events: list[Event], users: list[User],
            window_s: float = 86400.0) -> "BehaviorEngine":
        for u in users:
            self.user_roles[u.user_id] = u.role.value
            self.user_home[u.user_id] = u.home_geo

        windows = window_events(events, window_s)
        all_vecs: list[np.ndarray] = []
        role_vecs: dict[str, list[np.ndarray]] = {}

        for uid, wins in windows.items():
            home = self.user_home.get(uid, "IN-MH-Mumbai")
            vecs = [featurize_window(w, home) for w in wins if w]
            if not vecs:
                continue
            M = np.vstack(vecs)
            all_vecs.extend(vecs)
            if len(vecs) >= SETTINGS.model.min_events_for_baseline // 10 or len(vecs) >= 3:
                self.user_baselines[uid] = RobustBaseline(uid).fit(M)
            role = self.user_roles.get(uid, "unknown")
            role_vecs.setdefault(role, []).extend(vecs)

        X = np.vstack(all_vecs) if all_vecs else np.zeros((1, len(FEATURE_NAMES)))
        self.iforest.fit(X)
        self.autoenc.fit(X)
        self.peer_model.fit({r: np.vstack(v) for r, v in role_vecs.items()
                             if len(v) >= 3})
        self._fitted = True
        return self

    @property
    def iforest_backend(self) -> str:
        return self.iforest.backend

    # ---- scoring ----------------------------------------------------------
    def score_window(self, user_id: str, events: list[Event]) -> BehaviorScore:
        home = self.user_home.get(user_id, "IN-MH-Mumbai")
        x = featurize_window(events, home)
        X = x.reshape(1, -1)

        ae = float(self.autoenc.anomaly_score(X)[0]) if self._fitted else 0.0
        iso = float(self.iforest.anomaly_score(X)[0]) if self._fitted else 0.0
        self_dev = self.user_baselines[user_id].deviation(x) \
            if user_id in self.user_baselines else 0.0
        role = self.user_roles.get(user_id, "unknown")
        peer_dev = self.peer_model.deviation(role, x)

        # Weighted fusion → 0..1, then scale to 0..100.
        fused = (0.35 * ae + 0.30 * iso + 0.20 * self_dev + 0.15 * peer_dev)
        score = float(np.clip(fused, 0, 1) * 100)

        drivers = self._explain(user_id, role, x)
        return BehaviorScore(
            user_id=user_id, score=score, ae_anomaly=ae, iforest_anomaly=iso,
            self_deviation=self_dev, peer_deviation=peer_dev, drivers=drivers,
            feature_vector=[round(float(f), 3) for f in x],
        )

    @staticmethod
    def _phrase(name: str, z: float, ref: str) -> str:
        pretty = name.replace("_", " ")
        if z >= RobustBaseline.Z_CAP:
            return f"{pretty}: first-seen / far above {ref}"
        return f"{pretty}: {z:.1f}σ above {ref}"

    def _explain(self, user_id: str, role: str, x: np.ndarray) -> list[str]:
        reasons: list[str] = []
        bl = self.user_baselines.get(user_id)
        if bl:
            for name, z in bl.top_deviations(x, k=3):
                reasons.append(self._phrase(name, z, "own baseline"))
        if not reasons:
            for name, z in self.peer_model.top_deviations(role, x, k=2):
                reasons.append(self._phrase(name, z, f"{role} peers"))
        if self._fitted and len(reasons) < 3:
            for i in self.autoenc.top_feature_errors(x, k=2):
                tag = f"novel {FEATURE_NAMES[i].replace('_', ' ')}"
                if tag not in " ".join(reasons):
                    reasons.append(tag)
        return reasons[:4]

    def score_all(self, events: list[Event]) -> list[BehaviorScore]:
        """Score the most recent window per user in `events`."""
        windows = window_events(events, window_s=1e18)  # single bucket = all
        return [self.score_window(uid, wins[0]) for uid, wins in windows.items()
                if wins]
