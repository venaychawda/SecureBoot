"""Auth router — debug access gating and trust anchor key management.

POST /auth/debug-access  — gate debug access via ECDSA credential
POST /auth/rotate-key    — rotate a trust anchor key (OEM-root authorized)
GET  /auth/keys          — list registered trust anchor key IDs
"""
from __future__ import annotations

from fastapi import APIRouter, Request

from api.websocket import manager

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/debug-access")
async def debug_access(request: Request) -> dict:
    body = await request.json()
    sim = request.app.state.sim
    credential = bytes.fromhex(body["credential"])
    granted = sim.dm.gate_debug_access(credential)
    await manager.broadcast({
        "type": "debug_access",
        "granted": granted,
        "debug_locked": sim.ecu.debug_locked,
    })
    return {"access_granted": granted, "debug_locked": sim.ecu.debug_locked}


@router.post("/rotate-key")
async def rotate_key(request: Request) -> dict:
    body = await request.json()
    sim = request.app.state.sim
    new_key_id: str = body["new_key_id"]
    authorization_sig = bytes.fromhex(body["authorization_sig"])
    ok = sim.tam.rotate_key(new_key_id, authorization_sig)
    await manager.broadcast({
        "type": "key_rotation",
        "new_key_id": new_key_id,
        "success": ok,
    })
    return {"success": ok, "new_key_id": new_key_id}


@router.get("/keys")
async def list_keys(request: Request) -> dict:
    return {"key_ids": request.app.state.sim.tam.get_registered_key_ids()}
