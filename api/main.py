"""FastAPI backend for SecureBootLab simulation.

Exposes REST endpoints for ECU state management, boot, update, recovery,
and VTC test execution.  Real-time DEM + ECU state via WebSocket at
/ws/events.
"""
from __future__ import annotations

import types
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from api.websocket import manager
from sim.config import (
    DASHBOARD_ORIGIN,
    HSM_KEY_ID_BOOTLOADER,
    HSM_KEY_ID_DEBUG_AUTH,
    HSM_KEY_ID_OEM_ROOT,
    HSM_KEY_ID_OEM_SIGNING,
    NVM_STORE_PATH,
    WEBSOCKET_PATH,
)


def _create_sim(nvm_path: str | None = None) -> types.SimpleNamespace:
    """Instantiate a full simulation stack and return as a namespace."""
    from sim.attestation_service import AttestationService
    from sim.boot_rom import BootROM
    from sim.crypto_provider import CryptoProvider
    from sim.cryif import CryIf
    from sim.csm import CSM
    from sim.debug_manager import DebugManager
    from sim.dem import DEM
    from sim.ecu_state import ECUState
    from sim.hsm import HSM
    from sim.manifest_validator import ManifestValidator
    from sim.nvm import NvM
    from sim.recovery_manager import RecoveryManager
    from sim.secure_boot_manager import SecureBootManager
    from sim.security_logger import SecurityLogger
    from sim.trust_anchor_manager import TrustAnchorManager
    from sim.update_manager import UpdateManager
    from sim.version_manager import VersionManager

    nvm = NvM(path=nvm_path or NVM_STORE_PATH)
    dem = DEM()

    hsm = HSM()
    hsm.generate_key_pair(HSM_KEY_ID_OEM_ROOT)
    hsm.generate_key_pair(HSM_KEY_ID_OEM_SIGNING)
    hsm.generate_key_pair(HSM_KEY_ID_BOOTLOADER)
    hsm.generate_key_pair(HSM_KEY_ID_DEBUG_AUTH)

    cryif = CryIf(hsm)
    csm = CSM(cryif)
    ecu = ECUState()
    sl = SecurityLogger(dem, nvm)
    cp = CryptoProvider(csm)
    vm = VersionManager(nvm, sl)
    mv = ManifestValidator()
    tam = TrustAnchorManager(hsm, sl)
    att = AttestationService(csm, nvm, sl)
    br = BootROM(tam=tam, cp=cp, mv=mv, vm=vm, sl=sl, ecu=ecu, nvm=nvm)
    rm = RecoveryManager(cp=cp, sl=sl, nvm=nvm, ecu=ecu)
    um = UpdateManager(cp=cp, vm=vm, sl=sl, nvm=nvm)
    sbm = SecureBootManager(cp=cp, mv=mv, vm=vm, rm=rm, sl=sl, att=att, ecu=ecu, nvm=nvm)
    dm = DebugManager(ecu=ecu, nvm=nvm, hsm=hsm, sl=sl)

    return types.SimpleNamespace(
        nvm=nvm, dem=dem, hsm=hsm, cryif=cryif, csm=csm, ecu=ecu,
        sl=sl, cp=cp, vm=vm, mv=mv, tam=tam, att=att, br=br, rm=rm,
        um=um, sbm=sbm, dm=dm,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.sim = _create_sim()
    yield
    try:
        app.state.sim.nvm.flush()
    except Exception:
        pass


app = FastAPI(title="SecureBootLab API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[DASHBOARD_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from api.routers import auth, diagnostics, test_scenarios  # noqa: E402

app.include_router(auth.router)
app.include_router(diagnostics.router)
app.include_router(test_scenarios.router)


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket(WEBSOCKET_PATH)
async def websocket_endpoint(ws: WebSocket) -> None:
    await manager.connect(ws)
    sim = ws.app.state.sim
    await manager.broadcast_ecu_state(sim.ecu.to_dict())
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# ECU state
# ---------------------------------------------------------------------------

@app.get("/ecu/state")
async def get_ecu_state(request: Request) -> dict:
    return request.app.state.sim.ecu.to_dict()


@app.post("/ecu/reset")
async def reset_ecu(request: Request) -> dict:
    sim = request.app.state.sim
    from sim.ecu_state import BootPhase
    sim.ecu.transition(BootPhase.POWER_OFF)
    sim.ecu.boot_attempt_count = 0
    sim.ecu.last_failure_reason = None
    sim.ecu.attestation_hash = None
    state = sim.ecu.to_dict()
    await manager.broadcast_ecu_state(state)
    return {"reset": True, "ecu_state": state}


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

@app.post("/boot/start")
async def boot_start(request: Request) -> dict:
    sim = request.app.state.sim
    result = sim.br.power_on()
    state = sim.ecu.to_dict()
    await manager.broadcast_ecu_state(state)
    phase_str = result.phase_reached.value if hasattr(result.phase_reached, "value") else str(result.phase_reached)
    await manager.broadcast({
        "type": "boot_result",
        "success": result.success,
        "phase_reached": phase_str,
        "failure_reason": result.failure_reason,
    })
    return {
        "success": result.success,
        "phase_reached": phase_str,
        "failure_reason": result.failure_reason,
    }


@app.post("/boot/verify-bootloader")
async def boot_verify_bootloader(request: Request) -> dict:
    body = await request.json()
    sim = request.app.state.sim
    image = bytes.fromhex(body["image"])
    signature = bytes.fromhex(body["signature"])
    version = int(body["version"])
    ok = sim.br.verify_bootloader(image, signature, version)
    await manager.broadcast_ecu_state(sim.ecu.to_dict())
    return {"verified": ok}


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

@app.post("/recovery/enter")
async def recovery_enter(request: Request) -> dict:
    body = await request.json()
    sim = request.app.state.sim
    sim.rm.enter_recovery_mode(body.get("reason", "api_request"))
    state = sim.ecu.to_dict()
    await manager.broadcast_ecu_state(state)
    return {"recovery_entered": True, "ecu_state": state}


@app.post("/recovery/flash")
async def recovery_flash(request: Request) -> dict:
    body = await request.json()
    sim = request.app.state.sim
    image = bytes.fromhex(body["image"])
    signature = bytes.fromhex(body["signature"])
    ok = sim.rm.execute_recovery_flash(image, signature)
    await manager.broadcast_ecu_state(sim.ecu.to_dict())
    return {"flashed": ok}


@app.get("/recovery/status")
async def recovery_status(request: Request) -> dict:
    return request.app.state.sim.rm.get_recovery_status()


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

@app.post("/update/activate")
async def update_activate(request: Request) -> dict:
    body = await request.json()
    sim = request.app.state.sim
    package = bytes.fromhex(body["package"])
    signature = bytes.fromhex(body["signature"])
    version = int(body.get("version", 2))
    sim.nvm.write("pending_update_version", version)
    ok = sim.um.activate_update(package, signature)
    await manager.broadcast_ecu_state(sim.ecu.to_dict())
    return {"activated": ok, "update_status": sim.um.get_update_status()}


@app.post("/update/rollback")
async def update_rollback(request: Request) -> dict:
    sim = request.app.state.sim
    sim.um.rollback_update()
    await manager.broadcast_ecu_state(sim.ecu.to_dict())
    return {"rolled_back": True, "update_status": sim.um.get_update_status()}


@app.get("/update/status")
async def update_status(request: Request) -> dict:
    return request.app.state.sim.um.get_update_status()


# ---------------------------------------------------------------------------
# Dev / dashboard helpers  (demo use only — not part of SWR spec)
# ---------------------------------------------------------------------------

@app.get("/dev/test-image")
async def dev_test_image(request: Request) -> dict:
    """Return a fresh OEM-signed test firmware image for dashboard demonstrations."""
    from sim.config import HSM_KEY_ID_OEM_SIGNING
    sim = request.app.state.sim
    image = b"APPLICATION_IMAGE_V2_VALID_PAYLOAD_32BYTES_"
    sig = sim.hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
    return {
        "image": image.hex(),
        "signature": sig.hex(),
        "version": 2,
        "note": "OEM-signed via oem_signing_key — demo use only",
    }


@app.post("/dev/provision-app-image")
async def dev_provision_app_image(request: Request) -> dict:
    """Write a valid OEM-signed application image to NvM so boot/start succeeds."""
    from sim.config import HSM_KEY_ID_OEM_SIGNING
    sim = request.app.state.sim
    image = b"APPLICATION_IMAGE_V2_VALID_PAYLOAD_32BYTES_"
    sig = sim.hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
    sim.nvm.write("active_application_image", {
        "image": image.hex(),
        "sig": sig.hex(),
        "version": 2,
    })
    sim.nvm.write("pending_update_version", 3)
    await manager.broadcast({"type": "provisioned", "note": "Application image provisioned in NvM"})
    return {"provisioned": True, "version": 2}
