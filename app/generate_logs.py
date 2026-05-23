"""Headless log generator (no web UI).  Use ``app/api.py`` for the control panel."""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from engine import GeneratorEngine


def main() -> int:
    parser = argparse.ArgumentParser(description="Headless synthetic log generator for Wazuh home lab.")
    parser.add_argument("--config", required=True, type=Path, help="Runtime config JSON from render_lab.py.")
    parser.add_argument("--output-root", required=True, type=Path, help="Root directory for per-endpoint log files.")
    parser.add_argument(
        "--datasets-dir",
        type=Path,
        default=None,
        help="Optional directory containing real-world log datasets to replay.",
    )
    args = parser.parse_args()

    runtime = json.loads(args.config.read_text(encoding="utf-8"))
    engine = GeneratorEngine(runtime, args.output_root, datasets_dir=args.datasets_dir)
    engine.start()

    status = engine.status()
    print(f"Starting synthetic log generator for {status['endpoint_count']} endpoints; "
          f"seed={runtime.get('seed')!r}", flush=True)

    try:
        while True:
            time.sleep(30)
            s = engine.status()
            print(
                f"[{datetime.now(timezone.utc).isoformat()}] "
                f"endpoints={s['endpoint_count']} total_events={s['total_events']} "
                f"events_last_minute={s['events_last_minute']}",
                flush=True,
            )
    except KeyboardInterrupt:
        engine.stop()
        print("Synthetic log generator stopping.", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
