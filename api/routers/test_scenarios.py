"""VTC scenario runner — isolated simulation per test run.

POST /test/{vtc_id}/run    — run a named VTC in a fresh isolated sim
GET  /test/{vtc_id}/result — retrieve last result for a VTC
GET  /test/list            — list all available VTCs
"""
from __future__ import annotations

import tempfile
import time
import types
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from api.websocket import manager

router = APIRouter(prefix="/test", tags=["test"])

_results: dict[str, dict] = {}

_VTC_REGISTRY: dict[str, str] = {
    "VT-01": "Application image signature verification (valid and tampered)",
    "VT-02": "Secure boot with no stored image → SAFE_STATE",
    "VT-03": "Anti-rollback: monotonic counter enforcement",
    "VT-04": "Manifest validator: structural and temporal checks",
    "VT-05": "Recovery mode: enter and authenticated flash",
    "VT-06": "Debug manager: production lock and tamper detection",
    "VT-07": "Power-loss recovery: boot retry and lockout",
    "VT-08": "Tamper/glitch: HSM fail-mode detection",
    "VT-09": "Debug interface lock: production credential gate",
    "VT-10": "Attestation service: measure and generate report",
    "VT-11": "Boot ROM power-on: factory model golden path",
    "VT-12": "Version manager: validate, commit, floor semantics",
    "VT-13": "SecureBootManager full sequence with provisioned image",
    "VT-14": "Boot ROM end-to-end golden path",
    "VT-15": "Boot log hash-chain integrity protection",
    "VT-16": "TrustAnchorManager: key registration and boundary",
    "VT-17": "UpdateManager: atomic activate and rollback",
    "VT-18": "Performance timing (SKIP — timer-dependent)",
    "VT-19": "Environmental stress (SKIP — hardware only)",
    "VT-20": "Key rotation: OEM-authorized signing key rotation",
    "VT-21": "CryptoProvider: unknown key returns False (not exception)",
    "VT-22": "Certificate expiration: reject expired manifests",
}


def _fresh_sim() -> types.SimpleNamespace:
    """Create an isolated simulation stack backed by a temp NvM file."""
    from sim.attestation_service import AttestationService
    from sim.boot_rom import BootROM
    from sim.config import (
        HSM_KEY_ID_BOOTLOADER,
        HSM_KEY_ID_DEBUG_AUTH,
        HSM_KEY_ID_OEM_ROOT,
        HSM_KEY_ID_OEM_SIGNING,
    )
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

    nvm_path = tempfile.mktemp(suffix=".json")
    nvm = NvM(path=nvm_path)
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


def _run_vtc(vtc_id: str) -> dict[str, Any]:
    fn = _VTC_DISPATCH.get(vtc_id)
    if fn is None:
        return {"vtc_id": vtc_id, "status": "ERROR", "detail": "unknown VTC", "timestamp": time.time()}
    try:
        detail = fn()
        return {"vtc_id": vtc_id, "status": "PASS", "detail": detail, "timestamp": time.time()}
    except AssertionError as exc:
        return {"vtc_id": vtc_id, "status": "FAIL", "detail": str(exc) or "assertion failed", "timestamp": time.time()}
    except Exception as exc:
        return {"vtc_id": vtc_id, "status": "ERROR", "detail": f"{type(exc).__name__}: {exc}", "timestamp": time.time()}


# ---------------------------------------------------------------------------
# VTC scenario implementations
# ---------------------------------------------------------------------------

def _vt01() -> dict:
    """VT-01: Application image signature verification."""
    from sim.config import HSM_KEY_ID_OEM_SIGNING
    s = _fresh_sim()
    image = b"APPLICATION_IMAGE_V2_VALID_PAYLOAD_32BYTES_"
    sig = s.hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
    assert s.cp.verify_image_signature(image, sig, HSM_KEY_ID_OEM_SIGNING) is True
    tampered = image[:-4] + b"\xDE\xAD\xBE\xEF"
    assert s.cp.verify_image_signature(tampered, sig, HSM_KEY_ID_OEM_SIGNING) is False
    return {"valid_accepted": True, "tampered_rejected": True}


def _vt02() -> dict:
    """VT-02: Secure boot with no stored image → SAFE_STATE."""
    from sim.ecu_state import BootPhase
    s = _fresh_sim()
    result = s.sbm.run_boot_sequence()
    assert result.success is False
    assert s.ecu.boot_phase == BootPhase.SAFE_STATE
    return {"phase": s.ecu.boot_phase.value, "failure_reason": result.failure_reason}


def _vt03() -> dict:
    """VT-03: Anti-rollback monotonic counter enforcement."""
    from sim.config import FIRMWARE_VERSION_FLOOR_APP
    s = _fresh_sim()
    floor = FIRMWARE_VERSION_FLOOR_APP
    assert s.vm.validate_version("application", floor) is True
    s.vm.commit_version("application", floor)
    assert s.vm.validate_version("application", floor) is False, "replay must be blocked"
    assert s.vm.is_rollback("application", floor - 1) is True
    assert s.vm.is_rollback("application", floor) is False, "same-version is NOT a rollback"
    return {"floor": floor, "replay_blocked": True, "rollback_detected": True}


def _vt04() -> dict:
    """VT-04: Manifest validator structural and temporal checks."""
    import base64
    import json

    from cryptography.hazmat.primitives import hashes

    from sim.config import FIRMWARE_VERSION_FLOOR_APP, HSM_KEY_ID_OEM_SIGNING
    from sim.manifest_validator import ManifestError, ManifestValidator

    s = _fresh_sim()
    mv = ManifestValidator()
    image = b"BOOTLOADER_IMAGE_V2_VALID_PAYLOAD_32BYTES__"
    dh = hashes.Hash(hashes.SHA256())
    dh.update(image)
    img_hash = dh.finalize()
    sig = s.hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
    manifest = {
        "image_hash": base64.b64encode(img_hash).decode(),
        "signature": base64.b64encode(sig).decode(),
        "version": FIRMWARE_VERSION_FLOOR_APP + 1,
        "component": "BOOTLOADER",
        "key_id": HSM_KEY_ID_OEM_SIGNING,
        "not_before": "2020-01-01T00:00:00Z",
        "not_after": "2099-12-31T23:59:59Z",
    }
    result = mv.validate(json.dumps(manifest).encode())
    assert result.version == FIRMWARE_VERSION_FLOOR_APP + 1
    try:
        mv.validate(b"{ not valid json !!!")
        raise AssertionError("invalid JSON must raise ManifestError")
    except ManifestError:
        pass
    manifest["not_after"] = "2020-01-01T00:00:00Z"
    try:
        mv.validate(json.dumps(manifest).encode())
        raise AssertionError("expired cert must raise ManifestError")
    except ManifestError:
        pass
    return {"valid_accepted": True, "invalid_json_rejected": True, "expired_rejected": True}


def _vt05() -> dict:
    """VT-05: Recovery mode enter and authenticated flash."""
    from sim.config import HSM_KEY_ID_OEM_SIGNING
    from sim.ecu_state import BootPhase
    s = _fresh_sim()
    s.rm.enter_recovery_mode("test_recovery")
    assert s.ecu.boot_phase == BootPhase.SAFE_STATE
    image = b"RECOVERY_IMAGE_V2_VALID_PAYLOAD_32BYTES____"
    sig = s.hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
    assert s.rm.execute_recovery_flash(image, sig) is True
    assert s.rm.execute_recovery_flash(image, b"\x00" * 72) is False
    return {"recovery_entered": True, "authenticated_flash": True, "unauthenticated_rejected": True}


def _vt06() -> dict:
    """VT-06: Debug lock — NvM SB-disabled triggers tamper + DebugManagerError."""
    from sim.config import NVM_KEY_SECURE_BOOT_ENABLED
    from sim.debug_manager import DebugManagerError
    from sim.ecu_state import LifecycleState
    s = _fresh_sim()
    s.ecu.lifecycle = LifecycleState.PRODUCTION
    s.nvm.write(NVM_KEY_SECURE_BOOT_ENABLED, False)
    try:
        s.dm.check_debug_lock_on_startup()
        raise AssertionError("DebugManagerError expected")
    except DebugManagerError as exc:
        assert "secure_boot_disabled_in_production" in str(exc)
    assert s.ecu.secure_boot_enabled is True
    return {"tamper_detected": True, "sb_re_enforced": True}


def _vt07() -> dict:
    """VT-07: Power-loss recovery — boot retry and lockout."""
    from sim.config import MAX_BOOT_RETRY_ATTEMPTS, NVM_KEY_BOOT_COUNTER
    from sim.ecu_state import BootPhase
    s = _fresh_sim()
    s.nvm.write(NVM_KEY_BOOT_COUNTER, MAX_BOOT_RETRY_ATTEMPTS + 1)
    s.sbm.handle_interruption()
    assert s.ecu.boot_phase == BootPhase.LOCKED_OUT
    s2 = _fresh_sim()
    s2.nvm.write(NVM_KEY_BOOT_COUNTER, 1)
    s2.sbm.handle_interruption()
    assert s2.ecu.boot_phase == BootPhase.ROM_INIT
    return {"lockout_after_max": True, "retry_under_max": True, "max_attempts": MAX_BOOT_RETRY_ATTEMPTS}


def _vt08() -> dict:
    """VT-08: Tamper/glitch — HSM fail-mode raises CryptoProviderError."""
    from sim.config import HSM_KEY_ID_OEM_SIGNING
    from sim.crypto_provider import CryptoProviderError
    s = _fresh_sim()
    image = b"TEST_IMAGE_PAYLOAD"
    sig = s.hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
    s.hsm.simulate_failure(True)
    try:
        s.cp.verify_image_signature(image, sig, HSM_KEY_ID_OEM_SIGNING)
        raise AssertionError("CryptoProviderError expected when HSM is in fail-mode")
    except CryptoProviderError:
        pass
    return {"hsm_fail_mode_raises_CryptoProviderError": True}


def _vt09() -> dict:
    """VT-09: Debug interface lock — production credential gate."""
    from sim.config import HSM_KEY_ID_DEBUG_AUTH
    from sim.ecu_state import LifecycleState
    s = _fresh_sim()
    s.ecu.lifecycle = LifecycleState.PRODUCTION
    s.ecu.debug_locked = True
    challenge = b"debug_access_request_v1"
    valid_cred = s.hsm.sign(HSM_KEY_ID_DEBUG_AUTH, challenge)
    assert s.dm.gate_debug_access(valid_cred) is True
    assert s.dm.gate_debug_access(b"\x00" * 72) is False
    return {"valid_credential_accepted": True, "invalid_rejected": True}


def _vt10() -> dict:
    """VT-10: Attestation — measure component and generate report."""
    s = _fresh_sim()
    image = b"APPLICATION_IMAGE_V2_VALID_PAYLOAD_32BYTES_"
    digest = s.att.measure_component("application", image)
    assert len(digest) == 32
    report = s.att.generate_attestation_report()
    assert "application" in report["measurements"]
    return {"digest_length": len(digest), "report_has_measurement": True}


def _vt11() -> dict:
    """VT-11: Boot ROM power-on golden path (factory model)."""
    from sim.ecu_state import BootPhase
    s = _fresh_sim()
    result = s.br.power_on()
    assert result.success is True
    assert s.ecu.boot_phase == BootPhase.NORMAL_OPERATION
    return {"phase": s.ecu.boot_phase.value}


def _vt12() -> dict:
    """VT-12: VersionManager — validate, commit, floor semantics."""
    from sim.config import FIRMWARE_VERSION_FLOOR_APP
    s = _fresh_sim()
    floor = FIRMWARE_VERSION_FLOOR_APP
    assert s.vm.get_version("application") == floor
    assert s.vm.validate_version("application", floor) is True
    s.vm.commit_version("application", floor)
    assert s.vm.validate_version("application", floor) is False, "replay blocked after commit"
    assert s.vm.validate_version("application", floor + 1) is True
    return {"floor": floor, "floor_initially_accepted": True, "replay_blocked_after_commit": True}


def _vt13() -> dict:
    """VT-13: SecureBootManager full sequence with provisioned image."""
    from sim.config import HSM_KEY_ID_OEM_SIGNING
    from sim.ecu_state import BootPhase
    s = _fresh_sim()
    image = b"APPLICATION_IMAGE_V2_VALID_PAYLOAD_32BYTES_"
    sig = s.hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
    s.nvm.write("active_application_image", {"image": image.hex(), "sig": sig.hex(), "version": 2})
    result = s.sbm.run_boot_sequence()
    assert result.success is True
    assert s.ecu.boot_phase == BootPhase.NORMAL_OPERATION
    return {"phase": s.ecu.boot_phase.value, "success": True}


def _vt14() -> dict:
    """VT-14: Boot ROM end-to-end golden path."""
    from sim.ecu_state import BootPhase
    s = _fresh_sim()
    result = s.br.power_on()
    assert result.success is True
    assert s.ecu.boot_phase == BootPhase.NORMAL_OPERATION
    return {"phase": s.ecu.boot_phase.value}


def _vt15() -> dict:
    """VT-15: Boot log hash-chain integrity protection."""
    s = _fresh_sim()
    s.sl.log_boot_event("TEST_EVENT_1", {"step": 1})
    s.sl.log_boot_event("TEST_EVENT_2", {"step": 2})
    assert s.sl.verify_log_integrity() is True
    s.nvm.write("audit_log_hash_chain", "0" * 64)
    assert s.sl.verify_log_integrity() is False
    return {"chain_intact_initially": True, "tamper_detected": True}


def _vt16() -> dict:
    """VT-16: TrustAnchorManager key registration and boundary."""
    from sim.config import HSM_KEY_ID_OEM_SIGNING
    from sim.trust_anchor_manager import TrustAnchorError
    s = _fresh_sim()
    assert s.tam.is_key_registered(HSM_KEY_ID_OEM_SIGNING) is True
    assert s.tam.is_key_registered("nonexistent_key") is False
    pub = s.tam.get_oem_public_key(HSM_KEY_ID_OEM_SIGNING)
    assert pub.startswith(b"-----BEGIN PUBLIC KEY-----")
    try:
        s.tam.get_oem_public_key("unregistered_key")
        raise AssertionError("TrustAnchorError expected")
    except TrustAnchorError:
        pass
    return {"registered_accessible": True, "unregistered_raises": True}


def _vt17() -> dict:
    """VT-17: UpdateManager atomic activate and rollback."""
    from sim.config import HSM_KEY_ID_OEM_SIGNING
    s = _fresh_sim()
    img_v1 = b"APPLICATION_IMAGE_V1_PAYLOAD_32BYTES_______"
    sig_v1 = s.hsm.sign(HSM_KEY_ID_OEM_SIGNING, img_v1)
    s.nvm.write("active_application_image", {"image": img_v1.hex(), "sig": sig_v1.hex(), "version": 1})
    img_v2 = b"APPLICATION_IMAGE_V2_VALID_PAYLOAD_32BYTES_"
    sig_v2 = s.hsm.sign(HSM_KEY_ID_OEM_SIGNING, img_v2)
    s.nvm.write("pending_update_version", 2)
    ok = s.um.activate_update(img_v2, sig_v2)
    assert ok is True
    assert s.nvm.read("active_application_image")["version"] == 2
    s.um.rollback_update()
    assert s.nvm.read("active_application_image")["version"] == 1
    return {"activated": True, "rolled_back": True}


def _vt18() -> dict:
    """VT-18: Performance timing — skipped (timer-dependent)."""
    return {"status": "SKIPPED", "reason": "timer-dependent; run pytest --runslow"}


def _vt19() -> dict:
    """VT-19: Environmental stress — skipped (hardware only)."""
    return {"status": "SKIPPED", "reason": "hardware-only; run in Phase 2"}


def _vt20() -> dict:
    """VT-20: Key rotation — OEM-authorized signing key rotation."""
    from sim.config import HSM_KEY_ID_OEM_ROOT
    s = _fresh_sim()
    new_key_id = "oem_signing_key_v2"
    auth_sig = s.hsm.sign(HSM_KEY_ID_OEM_ROOT, new_key_id.encode())
    assert s.tam.rotate_key(new_key_id, auth_sig) is True
    assert s.tam.is_key_registered(new_key_id) is True
    assert s.tam.rotate_key("oem_signing_key_v3", b"\x00" * 72) is False
    return {"authorized_rotation": True, "unauthorized_rejected": True}


def _vt21() -> dict:
    """VT-21: CryptoProvider — unknown key returns False (not exception)."""
    from sim.config import HSM_KEY_ID_OEM_SIGNING
    s = _fresh_sim()
    image = b"TEST_IMAGE_PAYLOAD"
    sig = s.hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
    result = s.cp.verify_image_signature(image, sig, "nonexistent_key_id")
    assert result is False
    return {"unknown_key_returns_false": True}


def _vt22() -> dict:
    """VT-22: Certificate expiration — reject expired and future-dated manifests."""
    import base64
    import json

    from cryptography.hazmat.primitives import hashes

    from sim.config import FIRMWARE_VERSION_FLOOR_APP, HSM_KEY_ID_OEM_SIGNING
    from sim.manifest_validator import ManifestError, ManifestValidator

    s = _fresh_sim()
    mv = ManifestValidator()
    image = b"BOOTLOADER_IMAGE_V2_VALID_PAYLOAD_32BYTES__"
    dh = hashes.Hash(hashes.SHA256())
    dh.update(image)
    img_hash = dh.finalize()
    sig = s.hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
    base_manifest = {
        "image_hash": base64.b64encode(img_hash).decode(),
        "signature": base64.b64encode(sig).decode(),
        "version": FIRMWARE_VERSION_FLOOR_APP + 1,
        "component": "BOOTLOADER",
        "key_id": HSM_KEY_ID_OEM_SIGNING,
        "not_after": "2020-01-01T00:00:00Z",
    }
    try:
        mv.validate(json.dumps(base_manifest).encode())
        raise AssertionError("expired cert must raise ManifestError")
    except ManifestError:
        pass
    base_manifest["not_after"] = "2099-12-31T23:59:59Z"
    base_manifest["not_before"] = "2099-01-01T00:00:00Z"
    try:
        mv.validate(json.dumps(base_manifest).encode())
        raise AssertionError("future not_before must raise ManifestError")
    except ManifestError:
        pass
    return {"expired_rejected": True, "future_cert_rejected": True}


_VTC_DISPATCH: dict[str, Any] = {
    "VT-01": _vt01,
    "VT-02": _vt02,
    "VT-03": _vt03,
    "VT-04": _vt04,
    "VT-05": _vt05,
    "VT-06": _vt06,
    "VT-07": _vt07,
    "VT-08": _vt08,
    "VT-09": _vt09,
    "VT-10": _vt10,
    "VT-11": _vt11,
    "VT-12": _vt12,
    "VT-13": _vt13,
    "VT-14": _vt14,
    "VT-15": _vt15,
    "VT-16": _vt16,
    "VT-17": _vt17,
    "VT-18": _vt18,
    "VT-19": _vt19,
    "VT-20": _vt20,
    "VT-21": _vt21,
    "VT-22": _vt22,
}


# ---------------------------------------------------------------------------
# Router endpoints
# ---------------------------------------------------------------------------

@router.get("/list")
async def list_vtcs() -> dict:
    return {
        "vtcs": [
            {"vtc_id": k, "description": v}
            for k, v in sorted(_VTC_REGISTRY.items())
        ]
    }


@router.post("/{vtc_id}/run")
async def run_vtc(vtc_id: str, request: Request) -> dict:  # noqa: ARG001
    vtc_id = vtc_id.upper()
    if vtc_id not in _VTC_REGISTRY:
        raise HTTPException(status_code=404, detail=f"VTC {vtc_id} not found")
    result = _run_vtc(vtc_id)
    _results[vtc_id] = result
    await manager.broadcast({"type": "vtc_result", **result})
    return result


@router.get("/{vtc_id}/result")
async def get_vtc_result(vtc_id: str) -> dict:
    vtc_id = vtc_id.upper()
    if vtc_id not in _results:
        raise HTTPException(status_code=404, detail=f"No result for {vtc_id} — run it first")
    return _results[vtc_id]
