# Wazuh Home Lab

This repository builds a Wazuh training lab around two moving parts:

1. The official Wazuh single-node Docker stack.
2. A generated overlay stack with many synthetic Wazuh agents and a randomized log engine.

Each fake endpoint is a containerized Wazuh agent with its own hostname, agent name, groups, and training log directory. A synthetic log generator writes changing syslog-style events into each endpoint folder, so Wazuh sees distinct agents producing distinct activity instead of one static replay.

## What the lab does

- Boots the official Wazuh single-node stack from the upstream `wazuh/wazuh-docker` repository.
- Generates any number of fake endpoints from a single JSON config file.
- Auto-builds a Docker Compose overlay for synthetic agents.
- Produces randomized SSH, sudo, PAM, Apache, Nginx, Suricata, OpenVPN, kernel, cron, and generic syslog noise.
- Supports repeatable runs by setting a seed, or fully dynamic runs by leaving the seed unset.
- Lets you tune endpoint counts, naming, group membership, event frequency, burst behavior, and scenario weights per profile.

## Prerequisites

- Docker Desktop with WSL 2 enabled.
- Git.
- Python 3.11 or newer.
- On Windows, set the Docker host `vm.max_map_count` inside WSL before first startup:

```powershell
wsl -d <your-distro> -- sudo sysctl -w vm.max_map_count=262144
```

This mirrors the Wazuh Docker requirement for the indexer.

## Quick start

1. Copy the sample config.

```powershell
Copy-Item .\config\lab.example.json .\config\lab.json
```

2. Adjust endpoint counts, names, and scenario weights in `config/lab.json`.

3. Start the core stack plus synthetic overlay.

```powershell
.\scripts\up.ps1 -ConfigPath .\config\lab.json
```

4. Open `https://localhost`.

Default credentials from the official single-node stack:

- Username: `admin`
- Password: `SecretPassword`

5. Stop the lab when you are done.

```powershell
.\scripts\down.ps1 -ConfigPath .\config\lab.json
```

## Workflow

- `scripts/setup-core.ps1` clones the official `wazuh/wazuh-docker` repository into `vendor/wazuh-docker` and generates certificates for the single-node stack if they are missing.
- `scripts/render.ps1` expands the profile config into per-agent `ossec.conf` files, runtime metadata, and a Compose overlay file.
- `scripts/up.ps1` runs both steps and then starts:
  - the upstream single-node Wazuh core stack
  - the generated synthetic endpoint overlay
- `scripts/down.ps1` stops the overlay and optionally the core stack.

## Configuration model

The lab is driven by `config/lab.json` with three top-level sections:

- `wazuh`: version and manager connectivity settings.
- `lab`: Compose project names, generator image name, global tick rate, and optional random seed.
- `profiles`: endpoint profile definitions.

Each profile supports:

- `count`: how many endpoints to generate.
- `name_pattern`: Python-style format string using `{index}`.
- `groups`: Wazuh groups assigned during enrollment.
- `interval_seconds`: minimum and maximum delay between events.
- `burst_probability`: chance of a short event burst.
- `burst_size`: min/max burst length.
- `scenarios`: weighted scenario map.

Example:

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

## Generated files

The renderer writes everything under `generated/`:

- `generated/lab-compose.yml`: overlay stack for the fake endpoints.
- `generated/runtime/lab-runtime.json`: runtime metadata for the generator container.
- `generated/agents/<agent-name>/ossec.conf`: per-agent Wazuh agent config.
- `generated/training-data/<agent-name>/logs/training.log`: synthetic log files.

`generated/` is ignored in Git because it is derived output.

## Notes

- The official Wazuh core stack is intentionally kept upstream-aligned instead of re-implementing it here.
- The synthetic agent overlay joins the upstream Docker network through a deterministic Compose project name.
- Agents use Wazuh enrollment on port `1515` and send events over secure TCP on port `1514`, matching the official single-node manager config.
- If you set `registration_password`, the renderer writes an `authd.pass` file and wires it into each agent config.
- Bigger endpoint counts are possible, but Docker Desktop resources become the limiting factor before the generator does.
