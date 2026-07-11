"""Central tunables. Values chosen for a demoable, sensitive-but-not-noisy SOC."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RiskConfig:
    # Composite risk = weighted blend of behavioral anomaly, rule hits, and context.
    w_behavior: float = 0.40
    w_rules: float = 0.45
    w_context: float = 0.15
    # Exponential decay half-life (seconds) so risk cools down when behavior normalizes.
    decay_half_life_s: float = 6 * 3600
    # Access-policy thresholds (composite score 0-100).
    step_up_threshold: float = 40.0
    jit_threshold: float = 60.0
    deny_threshold: float = 80.0


@dataclass
class ModelConfig:
    contamination: float = 0.03          # expected anomaly fraction (IsolationForest)
    ae_hidden: tuple[int, ...] = (16, 8, 16)
    ae_epochs: int = 40
    ae_anomaly_percentile: float = 97.5  # reconstruction-error cut for "anomalous"
    min_events_for_baseline: int = 20
    random_state: int = 42


@dataclass
class PQCConfig:
    kem_alg: str = "ML-KEM-768"     # FIPS 203, NIST security cat. 3
    sig_alg: str = "ML-DSA-65"      # FIPS 204, NIST security cat. 3
    hybrid_x25519: bool = True      # belt-and-suspenders classical+PQC KEM
    aes_key_bytes: int = 32         # AES-256-GCM


@dataclass
class Settings:
    risk: RiskConfig = field(default_factory=RiskConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    pqc: PQCConfig = field(default_factory=PQCConfig)
    business_hours: tuple[int, int] = (8, 19)  # local hour window considered "normal"


SETTINGS = Settings()
