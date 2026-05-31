"""Ghost Sender — lightweight phantom Wazuh agents.

Registers every virtual endpoint as a real Wazuh agent (SSL handshake on
port 1515) and then forwards generated log events directly to the Wazuh
manager (TCP on port 1514) using the Wazuh agent wire protocol — all from
a single Python process running inside the lab-generator container.

This is an alternative to spinning up one ``wazuh/wazuh-agent`` Docker
container per endpoint.  Enable it by setting ``lab.agent_mode = "ghost"``
in your lab JSON config.

Protocol reference:
  https://github.com/Dwordcito/wazuh-agent-simulator
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import socket
import ssl
import struct
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad as _aes_pad
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

if TYPE_CHECKING:
    from engine import GeneratorEngine

log = logging.getLogger("ghost-sender")

# Fixed AES-CBC IV used by the Wazuh agent wire protocol.
_AES_IV = b"FEDCBA0987654321"

# Wazuh's local counter wraps at 9999 (matches src/os_crypto/shared/msgs.c).
_LOCAL_CTR_MAX = 9999


@dataclass
class _AgentCreds:
    agent_id: str
    name: str
    key: str
    enc_key: bytes  # 47 bytes; first 32 used as AES-256 key
    # Per-agent monotonic counters. Wazuh's anti-replay logic rejects any
    # message whose <global, local> is not strictly greater than the last
    # accepted one, so a fixed counter only ever lets the first event through.
    global_counter: int = 0
    local_counter: int = 0
    counter_lock: threading.Lock = field(default_factory=threading.Lock)


class GhostSender:
    """Runs all virtual endpoints as phantom Wazuh agents inside one process."""

    #: Maximum events to fetch per poll; set to engine.MAX_EVENTS so a single
    #: call always drains the entire in-memory buffer and never drops events.
    _FETCH_LIMIT = 2000

    RECONNECT_DELAY = 5.0   # seconds between TCP reconnect attempts
    POLL_INTERVAL = 0.3     # seconds between event-log polls
    REG_RETRIES = 5         # registration attempts before giving up on an endpoint
    REG_RETRY_DELAY = 4.0   # seconds between registration retries
    KEEPALIVE_INTERVAL = 30.0  # seconds between control keep-alive messages

    # The "location" field the manager sees for every forwarded event. Mirrors
    # the path a real wazuh-agent container would report when tailing
    # /training-data/logs/training.log via a <localfile> stanza, so the syslog
    # pre-decoder treats it like a normal log file and SSH / Apache / etc.
    # decoders fire as expected.
    LOG_LOCATION = "/training-data/logs/training.log"

    def __init__(
        self,
        engine: "GeneratorEngine",
        wazuh_config: dict,
        endpoints: list[dict],
    ) -> None:
        if not _CRYPTO_OK:
            raise RuntimeError(
                "pycryptodome is required for ghost-sender mode. "
                "Install it with: pip install pycryptodome"
            )
        self._engine = engine
        self._manager_address: str = wazuh_config["manager_address"]
        self._manager_port: int = int(wazuh_config["manager_port"])
        self._protocol: str = wazuh_config.get("manager_protocol", "tcp").lower()
        self._reg_port: int = int(wazuh_config["registration_port"])
        self._reg_password: str | None = wazuh_config.get("registration_password")

        # Full endpoint dicts from runtime config (include groups).
        self._endpoints: list[dict] = endpoints

        self._creds: dict[str, _AgentCreds] = {}
        self._threads: list[threading.Thread] = []
        self._registrar: threading.Thread | None = None
        self._lock = threading.Lock()
        self._running = False

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Kick off registration + sending in a background thread.

        Registration is slow (TLS handshake + retries against a manager that
        may still be booting), so it MUST NOT block the FastAPI lifespan —
        otherwise the generator's web UI never finishes coming up.
        """
        self._running = True
        log.info(
            "Ghost-sender: scheduling registration of %d phantom agents with %s:%d …",
            len(self._endpoints),
            self._manager_address,
            self._reg_port,
        )
        self._registrar = threading.Thread(
            target=self._register_and_launch_all,
            daemon=True,
            name="ghost-registrar",
        )
        self._registrar.start()

    def _register_and_launch_all(self) -> None:
        for ep in self._endpoints:
            if not self._running:
                return
            name = ep["name"]
            groups: list[str] = ep.get("groups", [])
            creds = self._register_with_retry(name, groups)
            if creds is None:
                log.warning(
                    "Ghost agent '%s' could not be registered — skipped for this run.",
                    name,
                )
                continue
            with self._lock:
                self._creds[name] = creds
            log.info("Ghost agent registered: '%s' (id=%s)", name, creds.agent_id)
            t = threading.Thread(
                target=self._sender_loop,
                args=(name,),
                daemon=True,
                name=f"ghost-{name}",
            )
            with self._lock:
                self._threads.append(t)
            t.start()
        log.info(
            "Ghost-sender: registration pass complete — %d/%d agents active.",
            len(self._creds),
            len(self._endpoints),
        )

    def stop(self) -> None:
        self._running = False

    # ── registration ──────────────────────────────────────────────────────────

    def _register_with_retry(self, name: str, groups: list[str]) -> _AgentCreds | None:
        delay = self.REG_RETRY_DELAY
        for attempt in range(1, self.REG_RETRIES + 1):
            try:
                return self._register_once(name, groups)
            except Exception as exc:
                if attempt < self.REG_RETRIES:
                    log.warning(
                        "Ghost '%s': registration attempt %d/%d failed (%s) — "
                        "retrying in %.0fs",
                        name, attempt, self.REG_RETRIES, exc, delay,
                    )
                    time.sleep(delay)
                    delay = min(delay * 2, 30.0)
                else:
                    log.error(
                        "Ghost '%s': all %d registration attempts failed: %s",
                        name, self.REG_RETRIES, exc,
                    )
        return None

    def _register_once(self, name: str, groups: list[str]) -> _AgentCreds:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw = socket.create_connection(
            (self._manager_address, self._reg_port), timeout=15
        )
        with ctx.wrap_socket(raw, server_hostname=self._manager_address) as ssl_sock:
            ssl_sock.settimeout(15)
            groups_str = ",".join(groups)
            if self._reg_password:
                if groups_str:
                    msg = f"OSSEC PASS: {self._reg_password} OSSEC A:'{name}' G:'{groups_str}'\n"
                else:
                    msg = f"OSSEC PASS: {self._reg_password} OSSEC A:'{name}'\n"
            else:
                if groups_str:
                    msg = f"OSSEC A:'{name}' G:'{groups_str}'\n"
                else:
                    msg = f"OSSEC A:'{name}'\n"
            ssl_sock.sendall(msg.encode())
            resp = ssl_sock.recv(4096).decode(errors="replace").strip()

        # Response format: "OSSEC K:'<id> <name> <ip> <key>'"
        try:
            key_str = resp.split("'")[1]
            parts = key_str.split(" ")
            agent_id, agent_key = parts[0], parts[3]
        except (IndexError, ValueError) as exc:
            raise RuntimeError(
                f"Unexpected authd response: {resp!r}"
            ) from exc

        enc_key = _derive_enc_key(agent_id, name, agent_key)
        return _AgentCreds(
            agent_id=agent_id, name=name, key=agent_key, enc_key=enc_key
        )

    # ── per-agent event loop ──────────────────────────────────────────────────

    def _sender_loop(self, endpoint_name: str) -> None:
        creds = self._creds[endpoint_name]
        # Start cursor at 0 so we pick up events generated during registration.
        cursor = 0
        sock: socket.socket | None = None
        startup_sent = False
        last_keepalive = 0.0

        while self._running:
            # Ensure we have an active connection.
            if sock is None:
                sock = self._connect(endpoint_name, creds)
                if sock is None:
                    time.sleep(self.RECONNECT_DELAY)
                    continue
                # New socket → re-greet the manager.
                startup_sent = False

            try:
                # Send the startup control message so the manager flips this
                # agent to "active" in agent-management views. Control messages
                # use the '#!-' prefix; the queue byte is omitted.
                if not startup_sent:
                    self._send_payload(sock, _build_payload(creds, b"#!-agent startup "))
                    startup_sent = True
                    last_keepalive = time.monotonic()

                # Periodic keep-alive so the agent stays "active".
                if time.monotonic() - last_keepalive >= self.KEEPALIVE_INTERVAL:
                    self._send_payload(sock, _build_payload(creds, b"#!-agent keep alive"))
                    last_keepalive = time.monotonic()

                # Drain new events for this endpoint from the engine's event log.
                events, cursor = self._engine.events_since(cursor, self._FETCH_LIMIT)
                for ev in events:
                    if ev["endpoint"] != endpoint_name:
                        continue
                    # Wazuh wire format for log lines: '1:<location>:<message>'.
                    # '1' is LOCALFILE_MQ; <location> is the file path the
                    # syslog decoder uses for source matching.
                    inner = (
                        f"1:{self.LOG_LOCATION}:{ev['message']}".encode(
                            "utf-8", errors="replace"
                        )
                    )
                    self._send_payload(sock, _build_payload(creds, inner))
            except OSError as exc:
                log.warning(
                    "Ghost '%s': send error (%s) - reconnecting ...",
                    endpoint_name, exc,
                )
                _close(sock)
                sock = None
                continue
            except Exception:
                log.exception("Ghost '%s': unexpected error in sender loop", endpoint_name)

            time.sleep(self.POLL_INTERVAL)

        _close(sock)

    def _send_payload(self, sock: socket.socket, payload: bytes) -> None:
        if self._protocol == "udp":
            sock.sendto(payload, (self._manager_address, self._manager_port))
        else:
            sock.settimeout(10)
            sock.sendall(struct.pack("<I", len(payload)) + payload)

    def _connect(self, name: str, creds: _AgentCreds) -> socket.socket | None:
        try:
            if self._protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.create_connection(
                    (self._manager_address, self._manager_port), timeout=10
                )
            return sock
        except OSError as exc:
            log.warning(
                "Ghost '%s': cannot connect to %s:%d (%s)",
                name, self._manager_address, self._manager_port, exc,
            )
            return None

    # ── status ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "mode": "ghost",
            "registered": len(self._creds),
            "active_threads": sum(1 for t in self._threads if t.is_alive()),
            "total_endpoints": len(self._endpoints),
            "agents": [
                {"name": c.name, "id": c.agent_id}
                for c in self._creds.values()
            ],
        }


# ── helpers ───────────────────────────────────────────────────────────────────

def _derive_enc_key(agent_id: str, name: str, key: str) -> bytes:
    """Return the 47-byte compound encryption key (first 32 = AES-256 key)."""
    sum2 = hashlib.md5(key.encode()).hexdigest().encode()          # 32 ASCII hex bytes
    sum1 = hashlib.md5(
        hashlib.md5(name.encode()).hexdigest().encode()
        + hashlib.md5(agent_id.encode()).hexdigest().encode()
    ).hexdigest().encode()[:15]
    return sum2 + sum1


def _build_payload(creds: _AgentCreds, message: bytes) -> bytes:
    """Encrypt and frame a single event for the Wazuh manager wire protocol.

    Wire layout (after AES-CBC decryption, padding stripped):
        <md5 hex 32B><rand 5B><global 10B>':'<local 4B>':'<message>

    Wazuh's manager checks the MD5, then enforces anti-replay on the
    <global, local> counters per agent — so they MUST increase across
    successive messages from the same agent.
    """
    with creds.counter_lock:
        creds.global_counter += 1
        creds.local_counter += 1
        if creds.local_counter > _LOCAL_CTR_MAX:
            creds.local_counter = 1
        gctr = creds.global_counter
        lctr = creds.local_counter

    rand_num = secrets.randbelow(100000)
    raw = f"{rand_num:05d}{gctr:010d}:{lctr:04d}:".encode("ascii") + message
    event = hashlib.md5(raw).hexdigest().encode() + raw

    # 2. Compress.
    compressed = zlib.compress(event)

    # 3. Pad to next 8-byte boundary with '!' prefix bytes.
    extra = len(compressed) % 8
    padded = (b"!" * (8 - extra if extra else 8)) + compressed

    # 4. AES-256-CBC encrypt (PKCS#7 block padding to 16-byte boundary).
    cipher = AES.new(creds.enc_key[:32], AES.MODE_CBC, _AES_IV)
    encrypted = cipher.encrypt(_aes_pad(padded, 16))

    # 5. Prepend Wazuh protocol header identifying the agent and cipher.
    return f"!{creds.agent_id}!#AES:".encode() + encrypted


def _close(sock: socket.socket | None) -> None:
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
