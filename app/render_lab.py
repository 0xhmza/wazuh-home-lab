from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from scenarios import SUPPORTED_SCENARIO_NAMES


DEFAULT_LAB = {
    "agent_mode": "container",
    "core_project_name": "wazuhlab-core",
    "generator_image_name": "wazuh-home-lab-generator",
    "lab_project_name": "wazuhlab-lab",
    "seed": None,
    "tick_seconds": 1,
}

DEFAULT_WAZUH = {
    "manager_address": "wazuh.manager",
    "manager_port": 1514,
    "manager_protocol": "tcp",
    "registration_password": None,
    "registration_port": 1515,
    "version": "4.14.5",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_interval(value: list[int], field_name: str) -> tuple[int, int]:
    require(isinstance(value, list) and len(value) == 2, f"{field_name} must be a two-item list.")
    minimum, maximum = value
    require(isinstance(minimum, int) and isinstance(maximum, int), f"{field_name} must contain integers.")
    require(minimum > 0 and maximum >= minimum, f"{field_name} must be positive and ordered.")
    return minimum, maximum


def normalize_config(raw: dict) -> dict:
    require(isinstance(raw, dict), "Config root must be a JSON object.")

    wazuh = {**DEFAULT_WAZUH, **raw.get("wazuh", {})}
    lab = {**DEFAULT_LAB, **raw.get("lab", {})}
    profiles = raw.get("profiles")

    require(isinstance(profiles, list) and profiles, "Config must include at least one profile.")
    require(isinstance(wazuh["version"], str) and wazuh["version"], "wazuh.version is required.")
    require(isinstance(wazuh["manager_address"], str) and wazuh["manager_address"], "wazuh.manager_address is required.")
    require(wazuh["manager_protocol"] in {"tcp", "udp"}, "wazuh.manager_protocol must be tcp or udp.")
    require(isinstance(wazuh["manager_port"], int) and wazuh["manager_port"] > 0, "wazuh.manager_port must be a positive integer.")
    require(
        isinstance(wazuh["registration_port"], int) and wazuh["registration_port"] > 0,
        "wazuh.registration_port must be a positive integer.",
    )
    require(isinstance(lab["core_project_name"], str) and lab["core_project_name"], "lab.core_project_name is required.")
    require(isinstance(lab["lab_project_name"], str) and lab["lab_project_name"], "lab.lab_project_name is required.")
    require(isinstance(lab["generator_image_name"], str) and lab["generator_image_name"], "lab.generator_image_name is required.")
    require(isinstance(lab["tick_seconds"], int) and lab["tick_seconds"] > 0, "lab.tick_seconds must be a positive integer.")
    require(lab["agent_mode"] in {"container", "ghost"}, "lab.agent_mode must be 'container' or 'ghost'.")

    normalized_profiles = []
    for profile in profiles:
        require(isinstance(profile, dict), "Each profile must be an object.")
        name = profile.get("name")
        count = profile.get("count")
        name_pattern = profile.get("name_pattern")
        scenarios = profile.get("scenarios")
        groups = profile.get("groups", ["training", name])
        interval_seconds = normalize_interval(profile.get("interval_seconds"), f"profiles[{name}].interval_seconds")
        burst_size = normalize_interval(profile.get("burst_size"), f"profiles[{name}].burst_size")
        burst_probability = profile.get("burst_probability")

        require(isinstance(name, str) and name, "Each profile requires a non-empty name.")
        require(isinstance(count, int) and count > 0, f"profiles[{name}].count must be a positive integer.")
        require(isinstance(name_pattern, str) and "{index" in name_pattern, f"profiles[{name}].name_pattern must include {{index}} formatting.")
        require(isinstance(groups, list) and groups, f"profiles[{name}].groups must be a non-empty list.")
        require(all(isinstance(group, str) and group for group in groups), f"profiles[{name}].groups entries must be non-empty strings.")
        require(
            isinstance(burst_probability, (int, float)) and 0 <= burst_probability <= 1,
            f"profiles[{name}].burst_probability must be between 0 and 1.",
        )
        require(isinstance(scenarios, dict) and scenarios, f"profiles[{name}].scenarios must be a non-empty object.")

        unknown = sorted(set(scenarios) - set(SUPPORTED_SCENARIO_NAMES))
        require(not unknown, f"profiles[{name}] contains unsupported scenarios: {', '.join(unknown)}")
        require(
            all(isinstance(weight, int) and weight > 0 for weight in scenarios.values()),
            f"profiles[{name}].scenarios weights must be positive integers.",
        )

        normalized_profiles.append(
            {
                "burst_probability": float(burst_probability),
                "burst_size": burst_size,
                "count": count,
                "groups": groups,
                "interval_seconds": interval_seconds,
                "name": name,
                "name_pattern": name_pattern,
                "scenarios": scenarios,
            }
        )

    version = wazuh["version"].lstrip("v")
    core_network = wazuh.get("core_network") or lab.get("core_network") or f"{lab['core_project_name']}_default"
    return {
        "lab": lab,
        "profiles": normalized_profiles,
        "supported_scenarios": list(SUPPORTED_SCENARIO_NAMES),
        "wazuh": {
            **wazuh,
            "core_network": core_network,
            "version": version,
        },
    }


def expand_endpoints(config: dict) -> list[dict]:
    endpoints = []
    for profile in config["profiles"]:
        for index in range(1, profile["count"] + 1):
            name = profile["name_pattern"].format(index=index)
            require(re.fullmatch(r"[A-Za-z0-9._-]{2,}", name) is not None, f"Endpoint name '{name}' contains unsupported characters.")
            endpoints.append(
                {
                    "burst_probability": profile["burst_probability"],
                    "burst_size": list(profile["burst_size"]),
                    "config_profiles": ["docker", "training", profile["name"]],
                    "groups": profile["groups"],
                    "interval_seconds": list(profile["interval_seconds"]),
                    "name": name,
                    "profile": profile["name"],
                    "scenarios": profile["scenarios"],
                }
            )

    names = [endpoint["name"] for endpoint in endpoints]
    require(len(names) == len(set(names)), "Generated endpoint names must be unique.")
    return endpoints


def xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def render_agent_config(endpoint: dict, config: dict) -> str:
    wazuh = config["wazuh"]
    config_profiles = ",".join(endpoint["config_profiles"])
    groups = ",".join(endpoint["groups"])
    password_block = ""
    if wazuh["registration_password"]:
        password_block = "\n      <authorization_pass_path>/var/ossec/etc/authd.pass</authorization_pass_path>"

    return (
        "<ossec_config>\n"
        "  <client>\n"
        "    <server>\n"
        f"      <address>{xml_escape(wazuh['manager_address'])}</address>\n"
        f"      <port>{wazuh['manager_port']}</port>\n"
        f"      <protocol>{wazuh['manager_protocol']}</protocol>\n"
        "    </server>\n"
        f"    <config-profile>{xml_escape(config_profiles)}</config-profile>\n"
        "    <notify_time>30</notify_time>\n"
        "    <time-reconnect>60</time-reconnect>\n"
        "    <auto_restart>yes</auto_restart>\n"
        "    <enrollment>\n"
        "      <enabled>yes</enabled>\n"
        f"      <manager_address>{xml_escape(wazuh['manager_address'])}</manager_address>\n"
        f"      <port>{wazuh['registration_port']}</port>\n"
        f"      <agent_name>{xml_escape(endpoint['name'])}</agent_name>\n"
        f"      <groups>{xml_escape(groups)}</groups>\n"
        "      <use_source_ip>no</use_source_ip>"
        f"{password_block}\n"
        "    </enrollment>\n"
        "  </client>\n"
        "\n"
        "  <localfile>\n"
        "    <log_format>syslog</log_format>\n"
        "    <location>/training-data/logs/*.log</location>\n"
        "    <only-future-events>yes</only-future-events>\n"
        "  </localfile>\n"
        "</ossec_config>\n"
    )


def sanitize_service_name(value: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", value.lower())


def render_compose(config: dict, endpoints: list[dict]) -> str:
    ui_port = config["lab"].get("ui_port", 8765)
    datasets_dir_present = config["lab"].get("datasets_dir_present", False)
    wazuh = config["wazuh"]
    agent_mode = config["lab"].get("agent_mode", "container")
    is_ghost = agent_mode == "ghost"

    lines: list[str] = [
        "services:",
        "  lab-generator:",
        f"    image: {config['lab']['generator_image_name']}",
        "    build:",
        "      context: ../",
        "      dockerfile: docker/log-generator/Dockerfile",
        "    restart: unless-stopped",
        "    ports:",
        f"      - \"{ui_port}:8080\"",
        "    command:",
        "      - python",
        "      - app/api.py",
        "      - --config",
        "      - /config/lab-runtime.json",
        "      - --output-root",
        "      - /training-data",
        "      - --datasets-dir",
        "      - /datasets",
        "      - --host",
        "      - 0.0.0.0",
        "      - --port",
        "      - '8080'",
    ]
    if is_ghost:
        lines.append("      - --ghost-sender")
    lines.extend(
        [
            "    volumes:",
            "      - ../generated/runtime/lab-runtime.json:/config/lab-runtime.json:ro",
            "      - ../generated/training-data:/training-data",
        ]
    )
    if datasets_dir_present:
        lines.append("      - ../datasets:/datasets:ro")
    lines.extend(["    networks:", "      - wazuh_core"])

    if not is_ghost:
        for endpoint in endpoints:
            service_name = sanitize_service_name(f"agent-{endpoint['name']}")
            groups_csv = ",".join(endpoint["groups"])
            lines.extend(
                [
                    f"  {service_name}:",
                    f"    image: wazuh/wazuh-agent:{wazuh['version']}",
                    f"    hostname: {endpoint['name']}",
                    "    restart: always",
                    "    depends_on:",
                    "      - lab-generator",
                    "    environment:",
                    f"      - WAZUH_MANAGER={wazuh['manager_address']}",
                    f"      - WAZUH_MANAGER_PORT={wazuh['manager_port']}",
                    f"      - WAZUH_PROTOCOL={wazuh['manager_protocol']}",
                    f"      - WAZUH_REGISTRATION_SERVER={wazuh['manager_address']}",
                    f"      - WAZUH_REGISTRATION_PORT={wazuh['registration_port']}",
                    f"      - WAZUH_AGENT_NAME={endpoint['name']}",
                    f"      - WAZUH_AGENT_GROUP={groups_csv}",
                ]
            )
            if wazuh["registration_password"]:
                lines.append("      - WAZUH_REGISTRATION_PASSWORD_PATH=/var/ossec/etc/authd.pass")

            lines.extend(
                [
                    "    volumes:",
                    f"      - ../generated/agents/{endpoint['name']}/ossec.conf:/wazuh-config-mount/etc/ossec.conf:ro",
                    f"      - ../generated/training-data/{endpoint['name']}:/training-data",
                ]
            )
            if wazuh["registration_password"]:
                lines.append(
                    f"      - ../generated/agents/{endpoint['name']}/authd.pass:/var/ossec/etc/authd.pass:ro"
                )

            lines.extend(["    networks:", "      - wazuh_core"])

    lines.extend(
        [
            "",
            "networks:",
            "  wazuh_core:",
            "    external: true",
            f"    name: {config['wazuh']['core_network']}",
            "",
        ]
    )
    return "\n".join(lines)


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def render(
    config_path: Path,
    repo_root: Path,
    core_network_override: str | None = None,
) -> tuple[Path, int]:
    config = normalize_config(load_config(config_path))
    if core_network_override:
        config["wazuh"]["core_network"] = core_network_override

    datasets_dir = repo_root / "datasets"
    config["lab"]["datasets_dir_present"] = datasets_dir.exists()

    endpoints = expand_endpoints(config)

    generated_root = repo_root / "generated"
    runtime_config_path = generated_root / "runtime" / "lab-runtime.json"
    compose_path = generated_root / "lab-compose.yml"

    runtime_payload: dict = {
        "seed": config["lab"]["seed"],
        "tick_seconds": config["lab"]["tick_seconds"],
        "endpoints": endpoints,
    }

    if config["lab"].get("agent_mode") == "ghost":
        runtime_payload["ghost_sender"] = {
            "manager_address": config["wazuh"]["manager_address"],
            "manager_port": config["wazuh"]["manager_port"],
            "manager_protocol": config["wazuh"]["manager_protocol"],
            "registration_port": config["wazuh"]["registration_port"],
            "registration_password": config["wazuh"]["registration_password"],
        }

    write_file(runtime_config_path, json.dumps(runtime_payload, indent=2) + "\n")
    write_file(compose_path, render_compose(config, endpoints))

    for endpoint in endpoints:
        agent_dir = generated_root / "agents" / endpoint["name"]
        write_file(agent_dir / "ossec.conf", render_agent_config(endpoint, config))
        if config["wazuh"]["registration_password"]:
            write_file(agent_dir / "authd.pass", f"{config['wazuh']['registration_password']}\n")

        log_dir = generated_root / "training-data" / endpoint["name"] / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / ".gitkeep").write_text("", encoding="utf-8")

    return compose_path, len(endpoints)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render the Wazuh home lab overlay stack.")
    parser.add_argument("--config", required=True, type=Path, help="Path to the lab JSON config.")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent, help="Repository root.")
    parser.add_argument(
        "--core-network",
        default=None,
        help="Override the auto-derived Wazuh core Docker network name. "
        "Use this when an existing Wazuh stack is running with a different project name.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    compose_path, endpoint_count = render(
        args.config.resolve(),
        args.repo_root.resolve(),
        core_network_override=args.core_network,
    )
    print(f"Rendered {endpoint_count} endpoints to {compose_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
