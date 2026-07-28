from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from sqlalchemy import select

from .api import internal, router
from .auth import router as auth_router
from .config import get_settings
from .database import SessionLocal, create_schema
from .events import hub
from .models import Admin, SystemState
from .security import hash_password, parse_session


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    settings.body_root.mkdir(parents=True, exist_ok=True)
    await create_schema()
    async with SessionLocal() as db:
        admin = await db.scalar(select(Admin).where(Admin.username == "admin"))
        if admin is None:
            db.add(Admin(username="admin", password_hash=hash_password(settings.admin_password)))
        if await db.get(SystemState, 1) is None:
            db.add(SystemState(id=1))
        await db.commit()
    yield


app = FastAPI(title="Mobile Traffic Inspector", version="0.1.0", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(router)
app.include_router(internal)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.websocket("/ws/live")
async def live(websocket: WebSocket) -> None:
    token = websocket.cookies.get("mti_session")
    if not token:
        await websocket.close(code=4401)
        return
    try:
        payload = parse_session(token, get_settings())
        async with SessionLocal() as db:
            admin = await db.get(Admin, payload["sub"])
            if admin is None or admin.session_version != int(payload["ver"]):
                raise ValueError
    except Exception:
        await websocket.close(code=4401)
        return
    await hub.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(websocket)


@app.exception_handler(Exception)
async def unhandled_error(_, exc: Exception) -> JSONResponse:
    # Never serialize request bodies, credentials, or exception internals.
    return JSONResponse({"detail": "internal server error"}, status_code=500)

