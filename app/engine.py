"""
Thread-safe generator engine.  Runs in a daemon thread while the FastAPI process
serves the control-plane API and web UI.
"""
from __future__ import annotations

import random
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from datasets import Dataset, load_datasets, merge_lines
from scenarios import SCENARIOS


class EndpointState:
    def __init__(self, cfg: dict) -> None:
        self._lock = threading.Lock()
        self.name: str = cfg["name"]
        self.profile: str = cfg["profile"]
        self.scenarios: dict[str, int] = dict(cfg["scenarios"])
        self.interval_seconds: list[float] = list(cfg["interval_seconds"])
        self.burst_probability: float = float(cfg["burst_probability"])
        self.burst_size: list[int] = list(cfg["burst_size"])
        self.paused: bool = False
        self.total_events: int = 0
        self.events_last_minute: int = 0

    # ── snapshots ────────────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "name": self.name,
                "profile": self.profile,
                "paused": self.paused,
                "total_events": self.total_events,
                "events_last_minute": self.events_last_minute,
                "scenarios": dict(self.scenarios),
                "interval_seconds": list(self.interval_seconds),
                "burst_probability": self.burst_probability,
                "burst_size": list(self.burst_size),
            }

    def patch(self, data: dict) -> None:
        with self._lock:
            if "scenarios" in data:
                self.scenarios = {k: max(0, int(v)) for k, v in data["scenarios"].items() if int(v) >= 0}
            if "interval_seconds" in data:
                lo, hi = data["interval_seconds"]
                self.interval_seconds = [max(0.1, float(lo)), max(float(lo), float(hi))]
            if "burst_probability" in data:
                self.burst_probability = max(0.0, min(1.0, float(data["burst_probability"])))
            if "burst_size" in data:
                lo, hi = data["burst_size"]
                self.burst_size = [max(1, int(lo)), max(int(lo), int(hi))]
            if "paused" in data:
                self.paused = bool(data["paused"])


class GeneratorEngine:
    """Manages all synthetic endpoints and drives the log-generation loop."""

    MAX_EVENTS = 2000

    def __init__(self, runtime: dict, output_root: Path, datasets_dir: Path | None = None) -> None:
        seed = runtime.get("seed")
        self._rng = random.Random(seed)
        self._tick = float(runtime.get("tick_seconds", 1))
        self._output_root = output_root

        # Real-world log datasets, if present. Picked into endpoint scenarios
        # via `dataset_replay`.
        self._datasets: dict[str, Dataset] = {}
        self._dataset_lines: list[str] = []
        if datasets_dir is not None:
            self._datasets = load_datasets(datasets_dir)
            self._dataset_lines = merge_lines(self._datasets)

        self._endpoints: dict[str, EndpointState] = {
            ep["name"]: EndpointState(ep) for ep in runtime["endpoints"]
        }
        self._next_emit: dict[str, float] = {
            name: time.monotonic() + self._rng.uniform(*ep.interval_seconds)
            for name, ep in self._endpoints.items()
        }

        self._global_paused = False
        self._storm_mode = False
        self._state_lock = threading.Lock()

        # Event log: list of (monotonic_index, event_dict)
        self._event_log: list[tuple[int, dict]] = []
        self._event_counter = 0
        self._event_lock = threading.Lock()

        self._minute_ts = time.monotonic()
        self._running = False
        self._thread: threading.Thread | None = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="lab-generator")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    # ── main loop ─────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while self._running:
            now = time.monotonic()

            # Reset per-minute event counters every 60 s
            if now - self._minute_ts >= 60:
                self._minute_ts = now
                for ep in self._endpoints.values():
                    with ep._lock:
                        ep.events_last_minute = 0

            with self._state_lock:
                paused = self._global_paused
                storm = self._storm_mode

            if not paused:
                for name, ep in self._endpoints.items():
                    with ep._lock:
                        ep_paused = ep.paused
                    if ep_paused:
                        continue

                    due = self._next_emit[name]
                    if storm:
                        due = now - 1  # always overdue in storm

                    if now >= due:
                        self._emit_for(ep, storm)
                        if storm:
                            delay = self._rng.uniform(0.05, 0.4)
                        else:
                            with ep._lock:
                                lo, hi = ep.interval_seconds
                            delay = self._rng.uniform(lo, hi)
                        self._next_emit[name] = now + delay

            time.sleep(self._tick)

    def _emit_for(self, ep: EndpointState, storm: bool) -> None:
        with ep._lock:
            burst_prob = ep.burst_probability if not storm else min(1.0, ep.burst_probability + 0.6)
            b_lo, b_hi = ep.burst_size
            if storm:
                b_lo, b_hi = max(b_lo, 5), max(b_hi, 15)
            scenarios = dict(ep.scenarios)

        burst = 1
        if self._rng.random() < burst_prob:
            burst = self._rng.randint(b_lo, b_hi)

        logs_dir = self._output_root / ep.name / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_file = logs_dir / "training.log"

        ep_meta = {
            "name": ep.name,
            "profile": ep.profile,
            "_dataset_lines": self._dataset_lines,
            "_datasets": self._datasets,
        }
        lines: list[tuple[str, str]] = []
        now_dt = datetime.now(timezone.utc)

        for offset in range(burst):
            scenario = self._pick(scenarios)
            fn = SCENARIOS.get(scenario)
            if fn is None:
                continue
            lines.append((scenario, fn(ep_meta, self._rng, now_dt + timedelta(seconds=offset))))

        if not lines:
            return

        with log_file.open("a", encoding="utf-8") as fh:
            fh.writelines(f"{msg}\n" for _, msg in lines)

        with ep._lock:
            ep.total_events += len(lines)
            ep.events_last_minute += len(lines)

        now_iso = datetime.now(timezone.utc).isoformat()
        with self._event_lock:
            for scenario, message in lines:
                self._event_counter += 1
                self._event_log.append((
                    self._event_counter,
                    {
                        "id": self._event_counter,
                        "endpoint": ep.name,
                        "profile": ep.profile,
                        "scenario": scenario,
                        "message": message,
                        "ts": now_iso,
                    },
                ))
            excess = len(self._event_log) - self.MAX_EVENTS
            if excess > 0:
                del self._event_log[:excess]

    def _pick(self, weights: dict[str, int]) -> str:
        active = {k: v for k, v in weights.items() if v > 0}
        if not active:
            return "generic_syslog_noise"
        total = sum(active.values())
        r = self._rng.uniform(0, total)
        acc = 0.0
        for name, w in active.items():
            acc += w
            if r <= acc:
                return name
        return next(iter(active))

    # ── API surface ───────────────────────────────────────────────────────────

    def status(self) -> dict:
        with self._state_lock:
            paused = self._global_paused
            storm = self._storm_mode
        return {
            "global_paused": paused,
            "storm_mode": storm,
            "endpoint_count": len(self._endpoints),
            "total_events": sum(ep.total_events for ep in self._endpoints.values()),
            "events_last_minute": sum(ep.events_last_minute for ep in self._endpoints.values()),
            "datasets": [
                {"name": d.name, "category": d.category, "line_count": len(d.lines)}
                for d in self._datasets.values()
            ],
            "dataset_lines_total": len(self._dataset_lines),
        }

    def endpoints(self) -> list[dict]:
        return [ep.snapshot() for ep in self._endpoints.values()]

    def endpoint(self, name: str) -> dict | None:
        ep = self._endpoints.get(name)
        return ep.snapshot() if ep else None

    def patch_endpoint(self, name: str, data: dict) -> dict | None:
        ep = self._endpoints.get(name)
        if ep is None:
            return None
        ep.patch(data)
        return ep.snapshot()

    def set_global_paused(self, paused: bool) -> None:
        with self._state_lock:
            self._global_paused = paused

    def set_storm(self, enabled: bool) -> None:
        with self._state_lock:
            self._storm_mode = enabled

    def apply_preset(self, preset_name: str, endpoint_name: str | None = None) -> bool:
        from presets import PRESETS
        preset = PRESETS.get(preset_name)
        if preset is None:
            return False
        targets = (
            [endpoint_name] if endpoint_name and endpoint_name in self._endpoints
            else list(self._endpoints)
        )
        for name in targets:
            self._endpoints[name].patch(preset)
        return True

    def events_since(self, cursor: int, limit: int = 100) -> tuple[list[dict], int]:
        with self._event_lock:
            candidates = [(i, e) for i, e in self._event_log if i > cursor]
        candidates = candidates[-limit:]
        new_cursor = candidates[-1][0] if candidates else cursor
        return [e for _, e in candidates], new_cursor
