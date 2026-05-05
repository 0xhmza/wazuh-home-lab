from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scenarios import SCENARIOS


def load_runtime(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def weighted_choice(weights: dict[str, int], rng: random.Random) -> str:
    total = sum(weights.values())
    choice = rng.uniform(0, total)
    running = 0.0
    for name, weight in weights.items():
        running += weight
        if choice <= running:
            return name
    return next(iter(weights))


def schedule_next(endpoint: dict, rng: random.Random) -> float:
    minimum, maximum = endpoint["interval_seconds"]
    return time.monotonic() + rng.uniform(minimum, maximum)


def emit_events(endpoint: dict, output_root: Path, rng: random.Random) -> int:
    logs_dir = output_root / endpoint["name"] / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / "training.log"

    burst_count = 1
    if rng.random() < endpoint["burst_probability"]:
        minimum, maximum = endpoint["burst_size"]
        burst_count = rng.randint(minimum, maximum)

    lines = []
    now = datetime.now(timezone.utc)
    for offset in range(burst_count):
        scenario_name = weighted_choice(endpoint["scenarios"], rng)
        scenario = SCENARIOS[scenario_name]
        event_time = now + timedelta(seconds=offset)
        lines.append(scenario(endpoint, rng, event_time))

    with log_file.open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(f"{line}\n")

    return burst_count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate synthetic per-endpoint training logs for Wazuh.")
    parser.add_argument("--config", required=True, type=Path, help="Runtime config JSON rendered by render_lab.py.")
    parser.add_argument("--output-root", required=True, type=Path, help="Root directory where per-endpoint training data should be written.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runtime = load_runtime(args.config)
    seed = runtime.get("seed")
    tick_seconds = runtime.get("tick_seconds", 1)
    rng = random.Random(seed)
    output_root = args.output_root
    endpoints = runtime["endpoints"]
    next_emit = {endpoint["name"]: schedule_next(endpoint, rng) for endpoint in endpoints}
    total_events = 0
    last_report = time.monotonic()

    print(f"Starting synthetic log generator for {len(endpoints)} endpoints; seed={seed!r}", flush=True)

    try:
        while True:
            for endpoint in endpoints:
                name = endpoint["name"]
                if time.monotonic() >= next_emit[name]:
                    total_events += emit_events(endpoint, output_root, rng)
                    next_emit[name] = schedule_next(endpoint, rng)

            if time.monotonic() - last_report >= 30:
                print(
                    f"[{datetime.now(timezone.utc).isoformat()}] endpoints={len(endpoints)} total_events={total_events}",
                    flush=True,
                )
                last_report = time.monotonic()

            time.sleep(tick_seconds)
    except KeyboardInterrupt:
        print("Synthetic log generator stopping.", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
