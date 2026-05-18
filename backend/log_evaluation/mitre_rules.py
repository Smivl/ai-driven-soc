#   MITRE ATT&CK  https://attack.mitre.org
###     INCLUDED
###         T1110,T1046,T1499,T1136,T1485,T1562,T1048,T1110.004

RULES = [
    { # T1110
        "id":         "T1110-brute-force",
        "label":      "Brute Force",
        "mitre":      "T1110",
        "category":   "authentication-failed",
        "threshold":  20,
        "window_s":   30,
    },
    {   # T1110 slow
        "id":         "T1110-slow-brute-force",
        "label":      "Slow Brute Force",
        "mitre":      "T1110",
        "category":   "authentication-failed",
        "threshold":  50,
        "window_s":   600,          # 10 min — catches low-and-slow
    },
    {   # T1046
        "id":         "T1046-port-scan",
        "label":      "Port Scan",
        "mitre":      "T1046",
        "category":   "connection-failed",
        "threshold":  15,
        "window_s":   10,
        "min_unique_ports": 10,     # extra guard: must span many ports
    },
    { # T1499
        "id":         "T1499-dos",
        "label":      "Denial of Service",
        "mitre":      "T1499",
        "category":   "connection-failed",
        "threshold":  200,
        "window_s":   10,
    },
    { # T1136
        "id":         "T1136-account-creation",
        "label":      "Suspicious Account Creation",
        "mitre":      "T1136",
        "category":   "user-creation",
        "threshold":  2,
        "window_s":   60,
    },
    { # T1485
        "id":         "T1485-data-destruction",
        "label":      "Data Destruction",
        "mitre":      "T1485",
        "category":   "file-deleted",
        "threshold":  10,
        "window_s":   60,
    },
    { # T1562
        "id":         "T1562-defense-evasion",
        "label":      "Defense Evasion / Config Tampering",
        "mitre":      "T1562",
        "category":   "system-configuration-changed",
        "threshold":  3,
        "window_s":   60,
    },
    
    # ── Multi-category rules ──────────────────────────────────────────────────

    { # T1048
        "id":       "T1048-exfiltration",
        "label":    "Data Exfiltration",
        "mitre":    "T1048",
        "multi_category": {
            "file-read":        5,   # 5+ file reads AND
            "network-traffic":  5,   #  5+ outbound network events
        },
        "window_s": 120,
    },
    { # T1110.004
        "id":       "T1110.004-credential-stuffing",
        "label":    "Credential Stuffing",
        "mitre":    "T1110.004",
        "multi_category": {
            "authentication-failed":  10,  # many failures AND
            "authentication-success":  1,  # at least one success
        },
        "window_s": 120,
    },
]
