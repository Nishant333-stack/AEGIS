"""AI-driven behavioral analytics (UEBA) for AEGIS."""
from aegis.analytics.features import FEATURE_NAMES, featurize_window, window_events
from aegis.analytics.engine import BehaviorEngine, BehaviorScore

__all__ = [
    "FEATURE_NAMES", "featurize_window", "window_events",
    "BehaviorEngine", "BehaviorScore",
]
