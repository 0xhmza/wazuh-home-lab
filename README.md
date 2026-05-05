# Wazuh Home Lab

A self-contained, fully configurable Wazuh training environment that spins up the official Wazuh single-node stack and populates it with an arbitrary number of synthetic endpoints, each running as a real Wazuh agent container and generating randomized, realistic syslog-style events continuously.

---

## How it works

```
┌─────────────────────────────────────────────────────┐
│                  Docker host                        │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │  Core stack  (wazuhlab-core)                 │   │
│  │  ┌────────────────┐  ┌──────────────────┐    │   │
│  │  │ wazuh.manager  │  │ wazuh.indexer    │    │   │
│  │  │  :1514 :1515   │  │    :9200         │    │   │
│  │  │  :514  :55000  │  └──────────────────┘    │   │
│  │  └───────┬────────┘  ┌──────────────────┐    │   │
│  │          │           │ wazuh.dashboard   │    │   │
│  │          │           │    :443           │    │   │
│  │          │           └──────────────────┘    │   │
│  └──────────┼───────────────────────────────────┘   │
│             │ wazuhlab-core_default network          │
│  ┌──────────┼───────────────────────────────────┐   │
│  │  Lab overlay  (wazuhlab-lab)                  │   │
│  │          │                                    │   │
│  │  ┌───────┴──────┐  ┌──────────┐              │   │
│  │  │ lab-generator│  │ agent-   │ × N          │   │
│  │  │  (Python)    │  │ <name>   │              │   │
│  │  │  writes logs │  │ Wazuh    │              │   │
│  │  │  to shared   │→ │ agent    │              │   │
│  │  │  bind mounts │  │ reads    │              │   │
│  │  └──────────────┘  │ logs →   │              │   │
│  │                    │ manager  │              │   │
│  │                    └──────────┘              │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

The **core stack** is the upstream `wazuh/wazuh-docker` single-node deployment, cloned on demand and started as-is. The **lab overlay** is generated from your config file and runs on the same Docker network, so every synthetic agent can enroll with and send events to the real manager.

The **lab-generator** container runs a Python process that:
- reads a runtime config produced by the renderer;
- schedules per-endpoint event emission using configurable random intervals;
- applies configurable burst behavior;
- picks each event's scenario by weighted random selection;
- writes randomized syslog-style log lines to per-endpoint bind-mount directories.

Each **agent container** (`wazuh/wazuh-agent`) has a mounted `ossec.conf` that:
- enrolls it with its own agent name and group membership;
- configures a `localfile` collector that tails the log files the generator writes.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker Desktop | Latest stable, **WSL 2 backend**. Must be running before `up.ps1`. |
| Docker Compose | Bundled with Docker Desktop on Windows. |
| Git | Used to clone `wazuh/wazuh-docker`. |
| Python 3.11+ | Only for the renderer; runs locally. Set `WAZUH_LAB_PYTHON` to override the detected binary. |
| WSL 2 | Required by Docker Desktop on Windows. |

### One-time WSL kernel setting

The Wazuh indexer requires a higher virtual memory map limit. Run this once in your WSL 2 distribution before the first startup:

```bash
sudo sysctl -w vm.max_map_count=262144
```

To make it permanent, add `vm.max_map_count=262144` to `/etc/sysctl.conf` inside WSL.

### System resources (single-node stack + 11 synthetic agents)

| Component | Minimum |
|---|---|
| CPU | 4 cores |
| RAM | 10 GB allocated to Docker |
| Disk | 60 GB free |

---

## Quick start

```powershell
# 1. Copy and optionally edit the config
Copy-Item .\config\lab.example.json .\config\lab.json

# 2. Start everything (clones wazuh-docker, generates certs, renders overlay, starts both stacks)
.\scripts\up.ps1 -ConfigPath .\config\lab.json
```

Open **https://localhost** after about 60 seconds.

| Credential | Value |
|---|---|
| Username | `admin` |
| Password | `SecretPassword` |

Agents appear under **Agent management → Summary** as they enroll. Enrollment takes 10–30 seconds per agent after the manager is ready.

```powershell
# Stop overlay + core
.\scripts\down.ps1 -ConfigPath .\config\lab.json

# Stop overlay only, keep manager/indexer/dashboard running
.\scripts\down.ps1 -ConfigPath .\config\lab.json -KeepCore
```

---

## Scripts reference

All scripts are in `scripts/`. Every script dot-sources `common.ps1`, which injects Docker Desktop's CLI directory into `PATH` automatically so you do not need to set it manually.

### `scripts/up.ps1`

Runs the full startup sequence.

```
up.ps1 [-ConfigPath <path>] [-SkipCoreSetup] [-SkipCertificateGeneration]
```

| Parameter | Default | Description |
|---|---|---|
| `-ConfigPath` | `.\config\lab.example.json` | Path to the lab JSON config. |
| `-SkipCoreSetup` | `$false` | Skip cloning/updating `wazuh-docker` and cert generation. Useful if the core stack is already running. |
| `-SkipCertificateGeneration` | `$false` | Skip cert generation only (still clones/updates). |

What it does, in order:
1. Calls `setup-core.ps1` to prepare the upstream Wazuh stack.
2. Calls `render.ps1` to generate per-agent configs and the overlay Compose file.
3. Starts the core stack with `docker compose -p wazuhlab-core up -d`.
4. Builds and starts the lab overlay with `docker compose -f generated/lab-compose.yml -p wazuhlab-lab up -d --build`.

### `scripts/down.ps1`

Stops running stacks.

```
down.ps1 [-ConfigPath <path>] [-KeepCore]
```

| Parameter | Default | Description |
|---|---|---|
| `-ConfigPath` | `.\config\lab.example.json` | Path to the lab JSON config. |
| `-KeepCore` | `$false` | Stop only the lab overlay; leave the core stack running. |

### `scripts/setup-core.ps1`

Clones or updates `wazuh/wazuh-docker` and generates TLS certificates.

```
setup-core.ps1 [-ConfigPath <path>] [-SkipCertificateGeneration]
```

The wazuh-docker repository is cloned into `vendor/wazuh-docker/` at the tag matching `wazuh.version` in your config. Certificates are generated once with the `wazuh-certs-generator` Docker image and reused on subsequent runs.

### `scripts/render.ps1`

Expands the config into derived artifacts under `generated/`.

```
render.ps1 [-ConfigPath <path>]
```

Calls `app/render_lab.py`. Safe to run at any time; re-running it overwrites the previous generated output.

---

## Configuration reference

The lab is driven by a single JSON file. Copy `config/lab.example.json` to `config/lab.json` and edit it.

### `wazuh` section

```json
"wazuh": {
  "version": "4.14.5",
  "manager_address": "wazuh.manager",
  "manager_port": 1514,
  "manager_protocol": "tcp",
  "registration_port": 1515,
  "registration_password": null
}
```

| Field | Type | Description |
|---|---|---|
| `version` | string | Wazuh version tag. Must match a `wazuh/wazuh-docker` Git tag. |
| `manager_address` | string | Hostname agents use to reach the manager. `wazuh.manager` is the service name on the shared Docker network. |
| `manager_port` | integer | Agent event port. Default `1514`. |
| `manager_protocol` | string | `tcp` or `udp`. Default `tcp`. |
| `registration_port` | integer | Enrollment port. Default `1515`. |
| `registration_password` | string or null | If set, written to `authd.pass` and wired into each agent config. Set `<use_password>yes</use_password>` in the manager's `ossec.conf` to enforce it. |

### `lab` section

```json
"lab": {
  "core_project_name": "wazuhlab-core",
  "lab_project_name": "wazuhlab-lab",
  "generator_image_name": "wazuh-home-lab-generator",
  "seed": null,
  "tick_seconds": 1
}
```

| Field | Type | Description |
|---|---|---|
| `core_project_name` | string | Docker Compose project name for the Wazuh core stack. Also used to derive the shared network name (`<project>_default`). |
| `lab_project_name` | string | Docker Compose project name for the lab overlay. |
| `generator_image_name` | string | Local image name to build/use for the log generator container. |
| `seed` | integer or null | RNG seed. `null` = fully random every run. Set to a fixed integer for reproducible output. |
| `tick_seconds` | integer | Polling interval (seconds) for the generator's main loop. Lower = more responsive scheduling; `1` is the default. |

### `profiles` section

An array of endpoint profile objects. Each profile generates `count` synthetic agents.

```json
{
  "name": "linux-workstation",
  "count": 6,
  "name_pattern": "wkst-{index:02d}",
  "groups": ["training", "linux-workstation"],
  "interval_seconds": [2, 8],
  "burst_probability": 0.18,
  "burst_size": [4, 10],
  "scenarios": {
    "ssh_invalid_user": 18,
    "ssh_failed_password": 22,
    "sudo_command": 12,
    "generic_syslog_noise": 19
  }
}
```

| Field | Type | Description |
|---|---|---|
| `name` | string | Profile identifier. Used in Wazuh config-profiles and group defaults. |
| `count` | integer | Number of endpoints to generate from this profile. |
| `name_pattern` | string | Python format string for agent names. Must contain `{index}`. Use `{index:02d}` for zero-padded numbers. |
| `groups` | array of strings | Wazuh groups assigned at enrollment. |
| `interval_seconds` | `[min, max]` | Random interval range in seconds between events per endpoint. |
| `burst_probability` | float `0–1` | Probability that an emission produces multiple events instead of one. |
| `burst_size` | `[min, max]` | Random number of events to emit in a burst (used when the burst check passes). |
| `scenarios` | object | Map of scenario name → integer weight. Weights do not need to sum to any specific value. |

---

## Available scenarios

| Scenario name | Log source | Example output |
|---|---|---|
| `ssh_invalid_user` | `sshd` | `Invalid user oracle from 103.24.5.1 port 48428` |
| `ssh_failed_password` | `sshd` | `Failed publickey for dave from 45.3.126.64 port 17930 ssh2` |
| `sudo_command` | `sudo` | `alice : TTY=pts/2 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id` |
| `pam_su_failure` | `su` | `pam_unix(su:auth): authentication failure; logname= uid=1000 …` |
| `kernel_usb_event` | `kernel` | `usb 2-3: New USB device found, idVendor=0781, manufacturer=SanDisk …` |
| `cron_session` | `CRON` | `pam_unix(cron:session): session opened for user root(uid=0) …` |
| `systemd_service_failure` | `systemd` | `nginx.service: Main process exited, code=exited, status=1/FAILURE` |
| `apache_404` | `apache2` | Apache combined log line with status 404, random path, random user-agent |
| `apache_500` | `apache2` | Apache combined log line with status 500 on `/api/v1/login` |
| `nginx_auth_failure` | `nginx` | `user "admin": password mismatch, client: 185.x.x.x …` |
| `suricata_alert` | `suricata` | Full Suricata fast-log format with real-looking SID and classification |
| `openvpn_tls_error` | `openvpn` | `TLS Error: incoming packet authentication failed from [AF_INET]…` |
| `generic_syslog_noise` | various | Background noise: NetworkManager, systemd timers, dockerd, NTP sync |

All IPs, ports, usernames, commands, HTTP paths, and user-agents are randomized on every emission. Burst events are timestamped one second apart within the burst.

---

## Repository layout

```
wazuh-home-lab/
│
├── app/
│   ├── generate_logs.py      # Generator: main loop, event scheduling, burst logic
│   ├── render_lab.py         # Renderer: config → ossec.conf + Compose overlay
│   └── scenarios.py          # All log-format functions and scenario registry
│
├── config/
│   └── lab.example.json      # Annotated sample configuration
│
├── docker/
│   └── log-generator/
│       └── Dockerfile        # python:3.11-slim, copies app/, CMD runs generate_logs.py
│
├── generated/                # Gitignored; all derived output lives here
│   ├── lab-compose.yml       # Generated Compose overlay
│   ├── runtime/
│   │   └── lab-runtime.json  # Flattened runtime config for the generator container
│   ├── agents/
│   │   └── <agent-name>/
│   │       ├── ossec.conf    # Per-agent Wazuh agent config (enrollment + localfile)
│   │       └── authd.pass    # Only present when registration_password is set
│   └── training-data/
│       └── <agent-name>/
│           └── logs/
│               └── training.log  # Synthetic syslog written by the generator
│
├── scripts/
│   ├── common.ps1            # Shared utilities; injects Docker Desktop into PATH
│   ├── up.ps1                # Full startup: setup-core → render → core up → overlay up
│   ├── down.ps1              # Stop overlay and/or core stack
│   ├── setup-core.ps1        # Clone/update wazuh-docker; generate TLS certificates
│   └── render.ps1            # Run the Python renderer
│
└── vendor/                   # Gitignored; upstream wazuh-docker clone lives here
    └── wazuh-docker/
        └── single-node/      # Source for the core stack Compose and certs
```

---

## Customizing the lab

### Add a new endpoint type

Add a new profile object to the `profiles` array in your `lab.json`:

```json
{
  "name": "database-server",
  "count": 2,
  "name_pattern": "db-{index:02d}",
  "groups": ["training", "database"],
  "interval_seconds": [5, 15],
  "burst_probability": 0.08,
  "burst_size": [2, 5],
  "scenarios": {
    "pam_su_failure": 30,
    "sudo_command": 25,
    "ssh_failed_password": 25,
    "generic_syslog_noise": 20
  }
}
```

Then re-render and restart the overlay:

```powershell
.\scripts\render.ps1 -ConfigPath .\config\lab.json
docker compose -f generated\lab-compose.yml -p wazuhlab-lab up -d --build
```

### Make runs reproducible

Set `"seed": 42` (or any integer) in the `lab` section. Every run with the same seed and same config produces the same sequence of events.

### Control event frequency

- Lower `interval_seconds` (e.g. `[1, 3]`) for a noisy endpoint.
- Raise `burst_probability` (e.g. `0.5`) for endpoints that tend to fire bursts.
- Raise `burst_size` max (e.g. `[10, 30]`) for high-volume spikes.

### Add a new scenario

1. Add a function to `app/scenarios.py` with the signature `(endpoint: dict, rng: random.Random, now: datetime) -> str`.
2. Register it in the `SCENARIOS` dict at the bottom of that file.
3. Use it by name in any profile's `scenarios` block.

---

## Troubleshooting

### Docker Desktop is not on PATH

The scripts inject `C:\Program Files\Docker\Docker\resources\bin` automatically. If Docker is installed elsewhere, set the full path in `WAZUH_LAB_PYTHON`'s equivalent for Docker, or add Docker to your system PATH.

### Agents show as disconnected immediately

The agent containers start before the manager is fully ready. Wazuh agents retry enrollment on a back-off schedule. Give it 60–120 seconds; agents will show as active once the manager accepts connections.

### Wazuh indexer fails to start

The indexer needs `vm.max_map_count=262144`. Run inside WSL:

```bash
sudo sysctl -w vm.max_map_count=262144
```

### Cannot connect to the Docker Engine

Docker Desktop must be running before you call `up.ps1`. The scripts do not auto-start Docker Desktop. If you launch it manually, wait until the system tray icon stops animating before running the scripts.

### Changing default passwords

The upstream single-node stack ships with default credentials. See the [official docs](https://documentation.wazuh.com/current/deployment-options/docker/changing-default-password.html) for how to rotate them.

### Resetting the lab completely

```powershell
# Stop everything
.\scripts\down.ps1

# Remove generated artifacts
Remove-Item -Recurse -Force generated

# Remove upstream clone (forces a fresh cert generation on next up)
Remove-Item -Recurse -Force vendor

# Remove persistent Docker volumes
docker volume ls --filter name=wazuhlab-core --quiet | ForEach-Object { docker volume rm $_ }
```

---

## Ports exposed by the core stack

| Port | Protocol | Service |
|---|---|---|
| 443 | HTTPS | Wazuh dashboard |
| 1514 | TCP | Agent event collection |
| 1515 | TCP | Agent enrollment (authd) |
| 514 | UDP | Syslog (remote) |
| 55000 | HTTPS | Wazuh manager REST API |
| 9200 | HTTPS | Wazuh indexer (OpenSearch) |

---

## References

- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Wazuh agent on Docker](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html#wazuh-agent)
- [ossec.conf localfile reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
- [ossec.conf client/enrollment reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html)
- [wazuh-logtest tool](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [wazuh/wazuh-docker on GitHub](https://github.com/wazuh/wazuh-docker)
