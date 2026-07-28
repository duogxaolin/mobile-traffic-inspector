"""mitmproxy WireGuard-mode capture addon.

The addon intentionally sends only metadata and encrypted-at-rest body paths to the
API. Body bytes are spooled directly to the shared encrypted volume, so a slow API
or a large upload cannot grow an in-memory buffer without bound.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import struct
import time
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mitmproxy import exceptions, http

from guard import client_allowed, resolve_destination

MAGIC = b"MTIB1\x00"
CHUNK_SIZE = 1024 * 1024
METADATA_HOSTS = {
    "169.254.169.254",
    "100.100.100.200",
    "168.63.129.16",
    "metadata.google.internal",
    "metadata.azure.internal",
}
SENSITIVE_LOG_RE = re.compile(r"(?i)(authorization|cookie|token|password|secret|api[_-]?key)")


def read_secret(name: str) -> str:
    path = os.getenv(f"{name}_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name}_FILE is required")
    return value


def decode_key() -> bytes:
    key = base64.b64decode(read_secret("APPLICATION_KEY"), validate=True)
    if len(key) != 32:
        raise RuntimeError("APPLICATION_KEY must decode to 32 bytes")
    return key


class BodyWriter:
    def __init__(self, root: Path, key: bytes, capture_id: str, direction: str) -> None:
        day = datetime.now(UTC).strftime("%Y/%m/%d")
        self.relative = f"{day}/{capture_id}-{direction}.mti"
        self.path = root / self.relative
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._source = self.path.open("wb")
        self._source.write(MAGIC)
        self._aes = AESGCM(key)
        self.size = 0
        self.closed = False

    def write(self, chunk: bytes) -> None:
        if self.closed or not chunk:
            return
        # One encrypted record per forwarded chunk. The plaintext chunk is bounded
        # by mitmproxy's streaming iterator and is capped defensively here.
        for offset in range(0, len(chunk), CHUNK_SIZE):
            plain = chunk[offset : offset + CHUNK_SIZE]
            nonce = os.urandom(12)
            encrypted = self._aes.encrypt(nonce, plain, b"mti-body-v1")
            self._source.write(struct.pack(">I", len(encrypted)))
            self._source.write(nonce)
            self._source.write(encrypted)
            self.size += len(plain)

    def close(self) -> None:
        if not self.closed:
            self._source.flush()
            self._source.close()
            self.closed = True


class InspectorAddon:
    def __init__(self) -> None:
        self.api_url = os.getenv("INSPECTOR_API_URL", "http://api:8000/internal/ingest")
        self.token = read_secret("INGEST_TOKEN")
        self.key = decode_key()
        self.body_root = Path(os.getenv("BODY_ROOT", "/var/lib/traffic-inspector/bodies"))
        self.spool_root = Path(os.getenv("CAPTURE_SPOOL", "/var/lib/traffic-inspector/spool"))
        self.state_root = Path(os.getenv("CAPTURE_STATE", "/var/lib/traffic-inspector/state"))
        self.max_queue = int(os.getenv("MAX_INGEST_QUEUE", "2048"))
        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=self.max_queue)
        self.writers: dict[tuple[str, str], BodyWriter] = {}
        self.flows: dict[str, dict] = {}
        self.sessions: dict[str, str] = {}
        self.recording = True
        self._worker_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._replay_task: asyncio.Task | None = None
        self._client: httpx.AsyncClient | None = None
        self._spooled = 0
        self._dropped = 0
        self.revoked_tunnel_ips: set[str] = set()
        overrides = [item.strip() for item in os.getenv("SAFE_DESTINATION_OVERRIDES", "").split(",") if item.strip()]
        self.overrides = set(overrides)

    async def running(self) -> None:
        self.body_root.mkdir(parents=True, exist_ok=True)
        self.spool_root.mkdir(parents=True, exist_ok=True)
        self.state_root.mkdir(parents=True, exist_ok=True)
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0))
        self._worker_task = asyncio.create_task(self._worker())
        self._heartbeat_task = asyncio.create_task(self._heartbeat())
        self._replay_task = asyncio.create_task(self._replay_spool())

    async def done(self) -> None:
        for writer in list(self.writers.values()):
            writer.close()
        for task in (self._worker_task, self._heartbeat_task, self._replay_task):
            if task:
                task.cancel()
        if self._client:
            await self._client.aclose()

    async def _heartbeat(self) -> None:
        while True:
            (self.state_root / "heartbeat").touch()
            (self.state_root / "metrics.json").write_text(
                json.dumps({
                    "queue": self.queue.qsize(),
                    "spooled": self._spooled,
                    "dropped": self._dropped,
                    "recording": self.recording,
                }),
                encoding="utf-8",
            )
            try:
                if self._client:
                    response = await self._client.get(
                        self.api_url.rsplit("/ingest", 1)[0] + "/control",
                        headers={"Authorization": f"Bearer {self.token}"},
                    )
                    if response.is_success:
                        control = response.json()
                        self.recording = bool(control.get("recording", True))
                        self.revoked_tunnel_ips = {
                            str(address) for address in control.get("revokedTunnelIps", []) if address
                        }
                    await self._client.post(
                        self.api_url.rsplit("/ingest", 1)[0] + "/metrics",
                        json={"spooled_events": self._spooled, "dropped_events": self._dropped},
                        headers={"Authorization": f"Bearer {self.token}"},
                    )
            except Exception:
                pass
            await asyncio.sleep(3)

    def _spool(self, event: dict) -> None:
        target = self.spool_root / f"events-{datetime.now(UTC):%Y%m%d}.jsonl"
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
        self._spooled += 1

    def enqueue(self, event: dict) -> None:
        if not self.recording:
            return
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                self._spool(event)
            except OSError:
                self._dropped += 1

    async def _worker(self) -> None:
        while True:
            event = await self.queue.get()
            try:
                await self._send(event)
            except Exception:
                try:
                    self._spool(event)
                except OSError:
                    self._dropped += 1
            finally:
                self.queue.task_done()

    async def _send(self, event: dict) -> None:
        if not self._client:
            self._spool(event)
            return
        response = await self._client.post(
            self.api_url,
            json=event,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        response.raise_for_status()

    async def _replay_spool(self) -> None:
        """Replay metadata after recovery; files are removed only after all sends succeed."""
        while True:
            try:
                for source in sorted(self.spool_root.glob("events-*.jsonl*")):
                    claimed = source.with_name(f"{source.name}.replaying-{uuid.uuid4().hex}")
                    try:
                        source.rename(claimed)
                    except FileNotFoundError:
                        continue
                    lines: list[str] = []
                    index = 0
                    try:
                        lines = claimed.read_text(encoding="utf-8").splitlines()
                        for index, line in enumerate(lines):
                            await self._send(json.loads(line))
                            index += 1
                    except Exception:
                        # A concurrent producer writes a fresh source file. Append the
                        # unsent claimed events to it before retaining no state only on
                        # success; a crash can duplicate, never lose, an event.
                        with source.open("a", encoding="utf-8") as target:
                            if lines[index:]:
                                target.write("\n".join(lines[index:]) + "\n")
                            target.flush()
                            os.fsync(target.fileno())
                        if lines:
                            claimed.unlink(missing_ok=True)
                    else:
                        claimed.unlink()
            except Exception:
                pass
            await asyncio.sleep(3)

    def _id(self, flow) -> str:
        return str(getattr(flow, "id", uuid.uuid4().hex))

    def _peer_ip(self, flow) -> str | None:
        for attr in ("peername", "address"):
            peer = getattr(getattr(flow, "client_conn", None), attr, None)
            if isinstance(peer, tuple) and peer:
                return str(peer[0])
            if isinstance(peer, str):
                return peer
        return None

    def _session_key(self, flow) -> str:
        device_ip = self._peer_ip(flow) or "unknown"
        key = self.sessions.get(device_ip)
        if not key:
            key = f"{device_ip}-{datetime.now(UTC):%Y%m%d}"
            self.sessions[device_ip] = key
        return key

    def _headers(self, headers) -> list[list[str]]:
        return [[name.decode("latin-1"), value.decode("latin-1")] for name, value in headers.fields]

    def _encrypted(self, value) -> str:
        nonce = os.urandom(12)
        plain = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
        return base64.b64encode(nonce + AESGCM(self.key).encrypt(nonce, plain, b"mti-json-v1")).decode()

    def _write_stream(self, flow, direction: str, chunks: Iterable[bytes]) -> Iterable[bytes]:
        if not self.recording:
            yield from chunks
            return
        writer = BodyWriter(self.body_root, self.key, self._id(flow), direction)
        self.writers[(self._id(flow), direction)] = writer
        try:
            for chunk in chunks:
                if chunk:
                    writer.write(chunk)
                yield chunk
        finally:
            writer.close()

    def _close_writer(self, flow, direction: str) -> tuple[str | None, int]:
        writer = self.writers.pop((self._id(flow), direction), None)
        if writer is None:
            return None, 0
        writer.close()
        return writer.relative, writer.size

    def guard_destination(self, host: str | None, port: int | None = None) -> str:
        resolved = resolve_destination(host, port, self.overrides)
        if not resolved:
            raise exceptions.KillFlow
        return resolved

    def pin_destination(self, server) -> None:
        address = getattr(server, "address", None)
        if not address:
            raise exceptions.KillFlow
        server.address = (self.guard_destination(address[0], address[1]), address[1])

    def guard_client(self, flow) -> None:
        peer_ip = self._peer_ip(flow)
        if not client_allowed(peer_ip, self.revoked_tunnel_ips):
            raise exceptions.KillFlow

    def server_connect(self, data) -> None:
        self.pin_destination(data.server)

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        try:
            self.guard_client(flow)
            self.guard_destination(flow.request.host, flow.request.port)
        except exceptions.KillFlow:
            raise
        capture_id = self._id(flow)
        self.flows[capture_id] = {"started": datetime.now(UTC), "session_key": self._session_key(flow)}
        flow.request.stream = lambda chunks: self._write_stream(flow, "request", chunks)
        if not self.recording:
            return
        split = urlsplit(flow.request.url)
        event = {
            "event": "headers",
            "capture_id": capture_id,
            "device_ip": self._peer_ip(flow),
            "session_key": self._session_key(flow),
            "protocol": f"HTTP/{flow.request.http_version}",
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": flow.request.host,
            "port": flow.request.port,
            "path": split.path or "/",
            "request_content_type": flow.request.headers.get("content-type"),
            "started_at": self.flows[capture_id]["started"].isoformat(),
            "request_headers_enc": self._encrypted(self._headers(flow.request.headers)),
            "url_enc": self._encrypted(flow.request.url),
            "query_enc": self._encrypted([[key, value] for key, value in parse_qsl(split.query, keep_blank_values=True)]),
        }
        self.enqueue(event)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        flow.response.stream = lambda chunks: self._write_stream(flow, "response", chunks)

    def _complete(self, flow: http.HTTPFlow, error: str | None = None) -> None:
        capture_id = self._id(flow)
        state = self.flows.pop(capture_id, {})
        request_path, request_size = self._close_writer(flow, "request")
        response_path, response_size = self._close_writer(flow, "response")
        if not self.recording:
            return
        completed = datetime.now(UTC)
        event = {
            "event": "error" if error else "complete",
            "capture_id": capture_id,
            "completed_at": completed.isoformat(),
            "status_code": getattr(getattr(flow, "response", None), "status_code", None),
            "response_content_type": getattr(getattr(flow, "response", None), "headers", {}).get("content-type") if getattr(flow, "response", None) else None,
            "response_headers_enc": self._encrypted(self._headers(flow.response.headers)) if getattr(flow, "response", None) else None,
            "request_body_path": request_path,
            "response_body_path": response_path,
            "request_body_size": request_size,
            "response_body_size": response_size,
            "duration_ms": int((completed - state.get("started", completed)).total_seconds() * 1000),
            "error_code": error,
            "error_enc": self._encrypted(str(getattr(flow, "error", ""))) if error else None,
            "not_captured_reason": "TLS/pinning/unsupported protocol" if error else None,
            "websocket": bool(getattr(flow, "websocket", None)),
        }
        self.enqueue(event)

    def response(self, flow: http.HTTPFlow) -> None:
        # responseheaders installs the streaming tee. This hook runs after all
        # response bytes have passed through it, so it is the point at which the
        # API can safely receive the encrypted body paths and final metadata.
        self._complete(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        self._complete(flow, getattr(flow.error, "msg", "proxy error") if flow.error else "proxy error")

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if not self.recording or not flow.websocket or not flow.websocket.messages:
            return
        message = flow.websocket.messages[-1]
        path = None
        size = len(message.content or b"")
        if size:
            writer = BodyWriter(self.body_root, self.key, self._id(flow), f"ws-{len(flow.websocket.messages)}")
            writer.write(message.content)
            writer.close()
            path = writer.relative
        self.enqueue(
            {
                "event": "websocket",
                "capture_id": self._id(flow),
                "sequence": len(flow.websocket.messages) - 1,
                "from_client": bool(message.from_client),
                "opcode": int(getattr(message, "type", 1)),
                "payload_path": path,
                "payload_size": size,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    def tcp_start(self, flow) -> None:
        try:
            self.guard_client(flow)
            self.pin_destination(flow.server_conn)
        except (exceptions.KillFlow, AttributeError):
            raise exceptions.KillFlow
        self.flows[self._id(flow)] = {"started": datetime.now(UTC), "session_key": self._session_key(flow)}
        if self.recording:
            self.enqueue({
                "event": "headers", "capture_id": self._id(flow), "device_ip": self._peer_ip(flow),
                "session_key": self._session_key(flow), "protocol": "TCP", "host": flow.server_conn.address[0],
                "port": flow.server_conn.address[1], "started_at": self.flows[self._id(flow)]["started"].isoformat(),
            })

    def tcp_message(self, flow) -> None:
        if not self.recording:
            return
        message = flow.messages[-1]
        writer = BodyWriter(self.body_root, self.key, self._id(flow), f"tcp-{len(flow.messages)}")
        writer.write(message.content)
        writer.close()
        self.enqueue({
            "event": "websocket", "capture_id": self._id(flow), "sequence": len(flow.messages) - 1,
            "from_client": bool(message.from_client), "opcode": 0, "payload_path": writer.relative,
            "payload_size": len(message.content), "timestamp": datetime.now(UTC).isoformat(),
        })

    def tcp_end(self, flow) -> None:
        self._complete(flow)

    def udp_start(self, flow) -> None:
        try:
            self.guard_client(flow)
            self.pin_destination(flow.server_conn)
        except (exceptions.KillFlow, AttributeError):
            raise exceptions.KillFlow
        self.flows[self._id(flow)] = {"started": datetime.now(UTC), "session_key": self._session_key(flow)}
        if self.recording:
            self.enqueue({
                "event": "headers", "capture_id": self._id(flow), "device_ip": self._peer_ip(flow),
                "session_key": self._session_key(flow), "protocol": "UDP", "host": str(flow.server_conn.address[0]),
                "port": flow.server_conn.address[1], "started_at": self.flows[self._id(flow)]["started"].isoformat(),
            })

    def udp_message(self, flow) -> None:
        return self.tcp_message(flow)

    def udp_end(self, flow) -> None:
        self._complete(flow)


addons = [InspectorAddon()]
