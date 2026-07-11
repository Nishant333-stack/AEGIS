"""Behavioral feature extraction.

Events for a (user, time-window) are aggregated into a fixed-order numeric
feature vector that captures the dimensions insider-threat research finds most
discriminative: volume, timing, data movement, privileged actions, access
breadth, and authentication friction. The same vector feeds the statistical
baselines, the Isolation Forest, and the autoencoder.
"""
from __future__ import annotations

import time
from collections import defaultdict

import numpy as np

from aegis.core.config import SETTINGS
from aegis.core.schema import ACTION_SENSITIVITY, Event, EventType

FEATURE_NAMES: list[str] = [
    "event_count",             # total activity volume
    "distinct_event_types",    # behavioral variety
    "after_hours_ratio",       # fraction outside business hours
    "weekend_ratio",           # fraction on weekends
    "failed_login_count",      # brute-force / credential-stuffing signal
    "log_total_bytes_out",     # log10 data egress
    "log_max_records",         # log10 largest single pull
    "priv_command_count",      # privileged operations
    "config_change_count",     # infra changes
    "unticketed_change_ratio", # changes without CAB ticket
    "usb_copy_count",          # removable-media exfil
    "external_upload_count",   # web/email exfil
    "distinct_hosts",          # lateral breadth
    "non_home_geo_ratio",      # impossible-travel / unusual location
    "pii_view_count",          # customer-data access
    "sensitivity_sum",         # sensitivity-weighted action load
]

_N = len(FEATURE_NAMES)


def _is_after_hours(ev: Event) -> bool:
    lo, hi = SETTINGS.business_hours
    return not (lo <= ev.hour() < hi)


def _is_weekend(ev: Event) -> bool:
    return time.localtime(ev.ts).tm_wday >= 5


def featurize_window(events: list[Event], home_geo: str = "IN-MH-Mumbai") -> np.ndarray:
    """Aggregate a list of events into the fixed-order feature vector."""
    v = np.zeros(_N, dtype=float)
    if not events:
        return v
    n = len(events)
    types = set()
    total_bytes = 0
    max_records = 0
    failed = priv_cmd = cfg = unticketed = usb = ext_up = pii = 0
    after = weekend = 0
    hosts = set()
    non_home = 0
    sens = 0.0

    for e in events:
        types.add(e.event_type)
        total_bytes += e.bytes_out
        max_records = max(max_records, e.records)
        hosts.add(e.host)
        sens += ACTION_SENSITIVITY.get(e.event_type, 0.2)
        if _is_after_hours(e):
            after += 1
        if _is_weekend(e):
            weekend += 1
        if e.event_type == EventType.LOGIN_FAILED:
            failed += 1
        if e.event_type in (EventType.PRIV_COMMAND, EventType.PRIV_ESCALATION_ATTEMPT):
            priv_cmd += 1
        if e.event_type in (EventType.CONFIG_CHANGE, EventType.ACCOUNT_CREATE,
                            EventType.ACCOUNT_PRIV_GRANT):
            cfg += 1
            if not e.change_ticket:
                unticketed += 1
        if e.event_type == EventType.FILE_COPY_USB:
            usb += 1
        if e.event_type in (EventType.HTTP_UPLOAD, EventType.EMAIL_EXTERNAL):
            ext_up += 1
        if e.event_type == EventType.CUSTOMER_PII_VIEW:
            pii += 1
        if e.geo != home_geo:
            non_home += 1

    v[0] = n
    v[1] = len(types)
    v[2] = after / n
    v[3] = weekend / n
    v[4] = failed
    v[5] = np.log10(total_bytes + 1)
    v[6] = np.log10(max_records + 1)
    v[7] = priv_cmd
    v[8] = cfg
    v[9] = (unticketed / cfg) if cfg else 0.0
    v[10] = usb
    v[11] = ext_up
    v[12] = len(hosts)
    v[13] = non_home / n
    v[14] = pii
    v[15] = sens
    return v


def window_events(events: list[Event], window_s: float = 86400.0
                  ) -> dict[str, list[list[Event]]]:
    """Group events by user then by fixed time-window bucket.

    Returns {user_id: [ [events_in_window0], [events_in_window1], ... ]}.
    """
    by_user: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_user[e.user_id].append(e)

    out: dict[str, list[list[Event]]] = {}
    for uid, evs in by_user.items():
        evs.sort(key=lambda e: e.ts)
        buckets: dict[int, list[Event]] = defaultdict(list)
        for e in evs:
            buckets[int(e.ts // window_s)].append(e)
        out[uid] = [buckets[k] for k in sorted(buckets)]
    return out
