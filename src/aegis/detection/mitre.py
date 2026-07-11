"""Subset of MITRE ATT&CK (Enterprise) techniques relevant to insider threat.

Mapping detections to ATT&CK gives analysts a shared language, supports
coverage reporting, and aligns with CISA / Center for Threat-Informed Defense
insider-threat guidance.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    tactic: str
    tid: str
    name: str


MITRE: dict[str, Technique] = {
    "valid_accounts": Technique("Initial Access / Privilege Escalation", "T1078",
                                "Valid Accounts"),
    "domain_accounts": Technique("Privilege Escalation", "T1078.003",
                                 "Valid Accounts: Local/Domain Accounts"),
    "brute_force": Technique("Credential Access", "T1110", "Brute Force"),
    "exfil_usb": Technique("Exfiltration", "T1052.001",
                           "Exfiltration over USB / Physical Medium"),
    "exfil_webservice": Technique("Exfiltration", "T1567",
                                  "Exfiltration Over Web Service"),
    "exfil_email": Technique("Exfiltration", "T1048",
                             "Exfiltration Over Alternative Protocol"),
    "create_account": Technique("Persistence", "T1136", "Create Account"),
    "account_manipulation": Technique("Persistence", "T1098",
                                      "Account Manipulation"),
    "abuse_elevation": Technique("Privilege Escalation", "T1548",
                                 "Abuse Elevation Control Mechanism"),
    "indicator_removal": Technique("Defense Evasion", "T1070",
                                   "Indicator Removal (Log Deletion)"),
    "impair_defenses": Technique("Defense Evasion", "T1562",
                                 "Impair Defenses"),
    "data_from_repo": Technique("Collection", "T1213",
                                "Data from Information Repositories"),
    "remote_services": Technique("Lateral Movement", "T1021",
                                 "Remote Services"),
    "scheduled_transfer": Technique("Exfiltration", "T1029",
                                    "Scheduled Transfer"),
}
