"""
Named attack presets.  Each preset is a partial EndpointState.patch() payload that
overrides scenarios, intervals, and burst settings.  PRESET_META drives the UI.
"""
from __future__ import annotations

PRESETS: dict[str, dict] = {
    "brute_force_storm": {
        "scenarios": {
            "ssh_failed_password": 40,
            "ssh_invalid_user": 35,
            "pam_su_failure": 14,
            "new_user_created": 6,
            "generic_syslog_noise": 5,
        },
        "interval_seconds": [0.5, 2.0],
        "burst_probability": 0.65,
        "burst_size": [8, 20],
    },
    "web_attack": {
        "scenarios": {
            "web_sql_injection": 22,
            "web_lfi_attempt": 18,
            "web_log4j_attempt": 14,
            "web_xss_attempt": 10,
            "apache_404": 15,
            "nginx_auth_failure": 12,
            "suricata_alert": 9,
        },
        "interval_seconds": [0.8, 3.0],
        "burst_probability": 0.45,
        "burst_size": [5, 16],
    },
    "lateral_movement": {
        "scenarios": {
            "lateral_ssh_hop": 25,
            "sudo_command": 20,
            "new_user_created": 15,
            "cron_persistence": 12,
            "ssh_accepted": 12,
            "sensitive_file_access": 10,
            "generic_syslog_noise": 6,
        },
        "interval_seconds": [3.0, 12.0],
        "burst_probability": 0.20,
        "burst_size": [2, 6],
    },
    "ransomware": {
        "scenarios": {
            "large_outbound_transfer": 22,
            "sensitive_file_access": 20,
            "process_injection_attempt": 18,
            "iptables_modified": 15,
            "systemd_service_failure": 12,
            "cron_persistence": 8,
            "generic_syslog_noise": 5,
        },
        "interval_seconds": [0.4, 2.5],
        "burst_probability": 0.75,
        "burst_size": [10, 30],
    },
    "apt_recon": {
        "scenarios": {
            "port_scan_detected": 30,
            "ssh_invalid_user": 18,
            "web_lfi_attempt": 14,
            "web_log4j_attempt": 12,
            "suricata_alert": 14,
            "openvpn_tls_error": 6,
            "generic_syslog_noise": 6,
        },
        "interval_seconds": [2.0, 10.0],
        "burst_probability": 0.25,
        "burst_size": [2, 8],
    },
    "insider_threat": {
        "scenarios": {
            "sudo_command": 18,
            "kernel_usb_event": 15,
            "large_outbound_transfer": 20,
            "sensitive_file_access": 22,
            "ssh_accepted": 10,
            "cron_persistence": 10,
            "iptables_modified": 5,
        },
        "interval_seconds": [5.0, 25.0],
        "burst_probability": 0.15,
        "burst_size": [2, 6],
    },
    "quiet": {
        "scenarios": {"generic_syslog_noise": 1},
        "interval_seconds": [30.0, 120.0],
        "burst_probability": 0.0,
        "burst_size": [1, 1],
    },
    "default": {
        "scenarios": {
            "ssh_invalid_user": 18,
            "ssh_failed_password": 22,
            "sudo_command": 12,
            "pam_su_failure": 8,
            "kernel_usb_event": 6,
            "cron_session": 8,
            "systemd_service_failure": 7,
            "generic_syslog_noise": 19,
        },
        "interval_seconds": [2.0, 8.0],
        "burst_probability": 0.18,
        "burst_size": [4, 10],
    },
}

PRESET_META: dict[str, dict] = {
    "brute_force_storm": {
        "label": "Brute Force Storm",
        "description": "High-volume SSH and authentication failures",
        "color": "#ef4444",
        "icon": "🔨",
    },
    "web_attack": {
        "label": "Web Attack",
        "description": "SQL injection, LFI, Log4Shell, XSS flooding",
        "color": "#8b5cf6",
        "icon": "🕸️",
    },
    "lateral_movement": {
        "label": "Lateral Movement",
        "description": "Internal SSH hops, privilege escalation, persistence",
        "color": "#f59e0b",
        "icon": "🦀",
    },
    "ransomware": {
        "label": "Ransomware",
        "description": "Exfiltration, firewall tampering, process injection",
        "color": "#dc2626",
        "icon": "💀",
    },
    "apt_recon": {
        "label": "APT Recon",
        "description": "Low-and-slow scanning, log4j probing",
        "color": "#06b6d4",
        "icon": "🔍",
    },
    "insider_threat": {
        "label": "Insider Threat",
        "description": "USB drops, sudo abuse, large data transfers",
        "color": "#d97706",
        "icon": "🕵️",
    },
    "quiet": {
        "label": "Go Quiet",
        "description": "Minimal background noise only",
        "color": "#475569",
        "icon": "🤫",
    },
    "default": {
        "label": "Reset to Default",
        "description": "Restore balanced scenario mix",
        "color": "#334155",
        "icon": "↺",
    },
}
