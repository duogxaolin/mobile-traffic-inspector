from __future__ import annotations

import asyncio
from collections import defaultdict
from uuid import UUID

from fastapi import WebSocket


class EventHub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(websocket)

    async def publish(self, event: dict) -> None:
        async with self._lock:
            targets = list(self._clients)
        dead: list[WebSocket] = []
        for socket in targets:
            try:
                await socket.send_json(event)
            except Exception:
                dead.append(socket)
        if dead:
            async with self._lock:
                for socket in dead:
                    self._clients.discard(socket)


hub = EventHub()

