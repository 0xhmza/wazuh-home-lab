"""FastAPI control panel for the Wazuh Home Lab generator.

Entry point: ``python app/api.py --config /config/lab-runtime.json --output-root /training-data``
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, StreamingResponse

from engine import GeneratorEngine
from ghost_sender import GhostSender

# Module-level singletons; initialised by main() before uvicorn starts.
_engine: GeneratorEngine | None = None
_ghost_sender: GhostSender | None = None
_dashboard_port: int = 0

_STATIC = Path(__file__).parent / "static"


# ── lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    _engine.start()  # type: ignore[union-attr]
    if _ghost_sender is not None:
        _ghost_sender.start()
    yield
    if _ghost_sender is not None:
        _ghost_sender.stop()
    _engine.stop()  # type: ignore[union-attr]


app = FastAPI(title="Wazuh Home Lab", lifespan=lifespan)


# ── UI ────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def ui():
    path = _STATIC / "index.html"
    return path.read_text(encoding="utf-8")


# ── status ────────────────────────────────────────────────────────────────────

@app.get("/api/status")
async def api_status():
    status = _engine.status()  # type: ignore[union-attr]
    if _ghost_sender is not None:
        status["ghost_sender"] = _ghost_sender.status()
    status["dashboard_port"] = _dashboard_port
    status["dashboard_url"] = (
        f"https://localhost:{_dashboard_port}" if _dashboard_port else "https://localhost"
    )
    return status


# ── endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/endpoints")
async def api_endpoints():
    return _engine.endpoints()  # type: ignore[union-attr]


@app.get("/api/endpoints/{name}")
async def api_endpoint(name: str):
    ep = _engine.endpoint(name)  # type: ignore[union-attr]
    if ep is None:
        raise HTTPException(404, f"Endpoint '{name}' not found")
    return ep


@app.patch("/api/endpoints/{name}")
async def api_patch_endpoint(name: str, body: dict):
    result = _engine.patch_endpoint(name, body)  # type: ignore[union-attr]
    if result is None:
        raise HTTPException(404, f"Endpoint '{name}' not found")
    return result


@app.post("/api/endpoints/{name}/pause")
async def api_pause(name: str):
    if _engine.patch_endpoint(name, {"paused": True}) is None:  # type: ignore[union-attr]
        raise HTTPException(404)
    return {"ok": True}


@app.post("/api/endpoints/{name}/resume")
async def api_resume(name: str):
    if _engine.patch_endpoint(name, {"paused": False}) is None:  # type: ignore[union-attr]
        raise HTTPException(404)
    return {"ok": True}


# ── global controls ───────────────────────────────────────────────────────────

@app.post("/api/global/pause")
async def api_global_pause():
    _engine.set_global_paused(True)  # type: ignore[union-attr]
    return {"ok": True}


@app.post("/api/global/resume")
async def api_global_resume():
    _engine.set_global_paused(False)  # type: ignore[union-attr]
    return {"ok": True}


@app.post("/api/global/storm")
async def api_storm_on():
    _engine.set_storm(True)  # type: ignore[union-attr]
    return {"ok": True}


@app.post("/api/global/normal")
async def api_storm_off():
    _engine.set_storm(False)  # type: ignore[union-attr]
    return {"ok": True}


# ── presets ───────────────────────────────────────────────────────────────────

@app.get("/api/presets")
async def api_presets():
    from presets import PRESETS, PRESET_META
    return [{"name": k, **PRESET_META.get(k, {})} for k in PRESETS]


@app.post("/api/presets/{preset_name}")
async def api_apply_preset(preset_name: str, endpoint: str | None = Query(default=None)):
    if not _engine.apply_preset(preset_name, endpoint):  # type: ignore[union-attr]
        raise HTTPException(404, f"Preset '{preset_name}' not found")
    return {"ok": True, "preset": preset_name}


# ── scenarios ─────────────────────────────────────────────────────────────────

@app.get("/api/scenarios")
async def api_scenarios():
    from scenarios import SCENARIOS, SCENARIO_META
    return [{"name": k, **SCENARIO_META.get(k, {})} for k in sorted(SCENARIOS)]


# ── events ────────────────────────────────────────────────────────────────────

@app.get("/api/events")
async def api_events(limit: int = Query(default=100, ge=1, le=500)):
    events, _ = _engine.events_since(0, limit)  # type: ignore[union-attr]
    return events


@app.get("/api/events/stream")
async def api_events_stream():
    """Server-Sent Events stream of live log events."""

    async def generator():
        # Bootstrap: send recent history so the feed isn't empty on connect.
        events, cursor = _engine.events_since(0, 200)  # type: ignore[union-attr]
        for ev in events:
            yield f"data: {json.dumps(ev)}\n\n"

        last_heartbeat = time.monotonic()
        while True:
            events, cursor = _engine.events_since(cursor, 100)  # type: ignore[union-attr]
            for ev in events:
                yield f"data: {json.dumps(ev)}\n\n"
            # Heartbeat to keep the connection alive through proxies.
            if time.monotonic() - last_heartbeat > 15:
                yield ": heartbeat\n\n"
                last_heartbeat = time.monotonic()
            await asyncio.sleep(0.3)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── CLI entry ─────────────────────────────────────────────────────────────────

def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="Wazuh Home Lab – web control panel")
    parser.add_argument("--config", required=True, type=Path, help="lab-runtime.json")
    parser.add_argument("--output-root", required=True, type=Path, help="training-data dir")
    parser.add_argument(
        "--datasets-dir",
        type=Path,
        default=None,
        help="Optional directory containing real-world log datasets to replay.",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--ghost-sender",
        action="store_true",
        help="Enable ghost-sender mode: register phantom Wazuh agents and forward "
             "events directly to the manager, replacing per-endpoint Docker containers. "
             "Requires 'ghost_sender' block in lab-runtime.json.",
    )
    args = parser.parse_args()

    runtime = json.loads(args.config.read_text(encoding="utf-8"))

    global _engine, _ghost_sender, _dashboard_port
    # The dashboard host port is picked by the launcher and threaded through to
    # the renderer; surface it to the web UI so links land on the correct URL.
    env_port = 0
    raw_env = os.environ.get("WAZUH_DASHBOARD_PORT", "").strip()
    if raw_env.isdigit():
        env_port = int(raw_env)
    _dashboard_port = env_port or int(runtime.get("dashboard_port", 0) or 0)

    _engine = GeneratorEngine(runtime, args.output_root, datasets_dir=args.datasets_dir)

    if args.ghost_sender:
        ghost_cfg = runtime.get("ghost_sender")
        if ghost_cfg is None:
            raise SystemExit(
                "ERROR: --ghost-sender requires a 'ghost_sender' block in "
                "lab-runtime.json. Re-render the lab with lab.agent_mode = 'ghost'."
            )
        _ghost_sender = GhostSender(
            engine=_engine,
            wazuh_config=ghost_cfg,
            endpoints=runtime.get("endpoints", []),
        )

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
