"""Loader for the CMU CERT Insider Threat Test Dataset (r4.2).

The CERT r4.2 corpus (CMU Software Engineering Institute / ExactData, DARPA
I2O) ships per-source CSVs — logon.csv, device.csv, file.csv, http.csv,
email.csv — plus LDAP org data and an `answers/` folder of labeled malicious
actors. This module maps those CSVs onto AEGIS's normalized `Event`/`User`
model so the exact same analytics pipeline runs on real logged data.

Download (free, registration): https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247
Place the extracted r4.2 files under a directory and pass it to `load_r42`.

The loader is intentionally dependency-light (pandas) and streams row-by-row
so multi-GB files don't need to fit in memory.
"""
from __future__ import annotations

import csv
import os
from datetime import datetime
from typing import Iterator

from aegis.core.schema import Event, EventType, Role, User

# CERT r4.2 does not label roles the way we do; we map its LDAP "role" strings
# heuristically. Anything unknown falls back to a low-privilege teller-like role.
_ROLE_HINTS = {
    "ITAdmin": Role.SYSADMIN, "SystemAdministrator": Role.SYSADMIN,
    "Database": Role.DBA, "NetworkEngineer": Role.NETWORK_ADMIN,
    "Auditor": Role.AUDITOR, "Salesman": Role.TELLER,
    "Director": Role.BRANCH_MANAGER, "Manager": Role.BRANCH_MANAGER,
}


def _parse_ts(s: str) -> float:
    # CERT format: "01/02/2010 07:11:45"
    for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
        try:
            return datetime.strptime(s.strip(), fmt).timestamp()
        except ValueError:
            continue
    return 0.0


def load_users(cert_dir: str) -> list[User]:
    """Read LDAP/psychometric CSVs (if present) into `User`s."""
    users: dict[str, User] = {}
    ldap_dir = os.path.join(cert_dir, "LDAP")
    search = [ldap_dir] if os.path.isdir(ldap_dir) else [cert_dir]
    for d in search:
        for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if not fn.endswith(".csv"):
                continue
            with open(os.path.join(d, fn), newline="") as fh:
                for row in csv.DictReader(fh):
                    uid = row.get("user_id") or row.get("employee_name") or row.get("user")
                    if not uid or uid in users:
                        continue
                    role_raw = (row.get("role") or "").replace(" ", "")
                    role = next((r for k, r in _ROLE_HINTS.items() if k in role_raw),
                                Role.TELLER)
                    users[uid] = User(
                        user_id=uid, name=row.get("employee_name", uid), role=role,
                        department=row.get("business_unit", "Unknown"),
                        privilege_level=4 if role in {Role.SYSADMIN, Role.DBA} else 1,
                    )
    return list(users.values())


def _iter_csv(path: str) -> Iterator[dict]:
    if not os.path.exists(path):
        return
    with open(path, newline="") as fh:
        yield from csv.DictReader(fh)


def load_r42(cert_dir: str, limit: int | None = None) -> Iterator[Event]:
    """Yield normalized `Event`s from a CERT r4.2 directory.

    Streams the five activity CSVs. `limit` caps total events (handy for demos).
    """
    n = 0

    def bump() -> bool:
        nonlocal n
        n += 1
        return limit is not None and n > limit

    for row in _iter_csv(os.path.join(cert_dir, "logon.csv")):
        act = (row.get("activity") or "").lower()
        yield Event(
            ts=_parse_ts(row.get("date", "")),
            user_id=row.get("user", "unknown"),
            event_type=EventType.LOGIN if "logon" in act else EventType.LOGOUT,
            host=row.get("pc", "unknown"),
        )
        if bump():
            return

    for row in _iter_csv(os.path.join(cert_dir, "device.csv")):
        yield Event(
            ts=_parse_ts(row.get("date", "")),
            user_id=row.get("user", "unknown"),
            event_type=EventType.FILE_COPY_USB, host=row.get("pc", "unknown"),
            target=row.get("activity", "USB"), bytes_out=1,
        )
        if bump():
            return

    for row in _iter_csv(os.path.join(cert_dir, "file.csv")):
        content = row.get("content", "")
        yield Event(
            ts=_parse_ts(row.get("date", "")),
            user_id=row.get("user", "unknown"),
            event_type=EventType.FILE_ACCESS, host=row.get("pc", "unknown"),
            target=row.get("filename", ""), bytes_out=len(content),
        )
        if bump():
            return

    for row in _iter_csv(os.path.join(cert_dir, "http.csv")):
        url = row.get("url", "")
        yield Event(
            ts=_parse_ts(row.get("date", "")),
            user_id=row.get("user", "unknown"),
            event_type=EventType.HTTP_UPLOAD, host=row.get("pc", "unknown"),
            target=url[:80], bytes_out=len(row.get("content", "")),
        )
        if bump():
            return

    for row in _iter_csv(os.path.join(cert_dir, "email.csv")):
        size = int(row.get("size", "0") or 0)
        recipients = row.get("to", "")
        external = any("dtaa.com" not in r for r in recipients.split(";") if r)
        yield Event(
            ts=_parse_ts(row.get("date", "")),
            user_id=row.get("user", "unknown"),
            event_type=EventType.EMAIL_EXTERNAL if external else EventType.FILE_ACCESS,
            host=row.get("pc", "unknown"), bytes_out=size, target=recipients[:80],
        )
        if bump():
            return


def load_answers(cert_dir: str) -> set[str]:
    """Return the set of known-malicious user_ids from the `answers/` folder."""
    malicious: set[str] = set()
    ans = os.path.join(cert_dir, "answers")
    if not os.path.isdir(ans):
        return malicious
    for root, _, files in os.walk(ans):
        for fn in files:
            if not fn.endswith(".csv"):
                continue
            for row in _iter_csv(os.path.join(root, fn)):
                uid = row.get("user") or row.get("user_id")
                if uid:
                    malicious.add(uid)
    return malicious
