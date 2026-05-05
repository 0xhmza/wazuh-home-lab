from __future__ import annotations

import random
import string
from datetime import datetime, timezone


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
    cron_pid = rng.randint(1000, 20000)
    return (
        f"{prefix(now, endpoint['name'], f'CRON[{cron_pid}]')} "
        f"pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)"
    )


def systemd_service_failure(endpoint: dict, rng: random.Random, now: datetime) -> str:
    service = rng.choice(SERVICES)
    return (
        f"{prefix(now, endpoint['name'], 'systemd[1]')} {service}.service: Main process exited, "
        f"code=exited, status={rng.choice([1, 2, 203, 255])}/FAILURE"
    )


def apache_404(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], f'apache2[{rng.randint(1000, 9000)}]')} "
        f"{public_ip(rng)} - - [{apache_timestamp(now)}] \"GET {rng.choice(HTTP_PATHS)} HTTP/1.1\" "
        f"404 {rng.randint(200, 2500)} \"-\" \"{rng.choice(USER_AGENTS)}\""
    )


def apache_500(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], f'apache2[{rng.randint(1000, 9000)}]')} "
        f"{public_ip(rng)} - - [{apache_timestamp(now)}] \"POST /api/v1/login HTTP/1.1\" "
        f"500 {rng.randint(500, 3000)} \"https://portal.example.invalid/login\" \"{rng.choice(USER_AGENTS)}\""
    )


def nginx_auth_failure(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], f'nginx[{rng.randint(1000, 9000)}]')} *{rng.randint(10, 999)} "
        f"user \"admin\": password mismatch, client: {public_ip(rng)}, server: "
        f"portal.example.invalid, request: \"GET /admin HTTP/1.1\", host: \"portal.example.invalid\""
    )


def suricata_alert(endpoint: dict, rng: random.Random, now: datetime) -> str:
    destination_port = rng.choice([22, 80, 443, 8080, 8443])
    return (
        f"{prefix(now, endpoint['name'], f'suricata[{rng.randint(1000, 9000)}]')} "
        f"[1:{rng.randint(2000000, 2099999)}:{rng.randint(1, 5)}] {rng.choice(SURICATA_SIGNATURES)} "
        f"[Classification: Attempted Information Leak] [Priority: {rng.choice([1, 2, 3])}] "
        f"{{TCP}} {public_ip(rng)}:{rng.randint(1024, 65535)} -> {private_ip(rng)}:{destination_port}"
    )


def openvpn_tls_error(endpoint: dict, rng: random.Random, now: datetime) -> str:
    return (
        f"{prefix(now, endpoint['name'], f'openvpn[{rng.randint(1000, 9000)}]')} TLS Error: incoming "
        f"packet authentication failed from [AF_INET]{public_ip(rng)}:{rng.randint(1024, 65535)}"
    )


def generic_syslog_noise(endpoint: dict, rng: random.Random, now: datetime) -> str:
    message = rng.choice(SYSLOG_NOISE_MESSAGES)
    if message.startswith(("systemd", "CRON", "NetworkManager", "dockerd", "systemd-timesyncd")):
        return f"{syslog_timestamp(now)} {endpoint['name']} {message}"
    return f"{prefix(now, endpoint['name'], 'syslogd')} {message}"


SCENARIOS = {
    "apache_404": apache_404,
    "apache_500": apache_500,
    "cron_session": cron_session,
    "generic_syslog_noise": generic_syslog_noise,
    "kernel_usb_event": kernel_usb_event,
    "nginx_auth_failure": nginx_auth_failure,
    "openvpn_tls_error": openvpn_tls_error,
    "pam_su_failure": pam_su_failure,
    "ssh_failed_password": ssh_failed_password,
    "ssh_invalid_user": ssh_invalid_user,
    "sudo_command": sudo_command,
    "suricata_alert": suricata_alert,
    "systemd_service_failure": systemd_service_failure,
}

SUPPORTED_SCENARIO_NAMES = tuple(sorted(SCENARIOS))
