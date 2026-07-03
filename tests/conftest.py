"""Shared pytest fixtures for SecureBootLab VTC test suite.

Extended from automotive-cyber-skills/test-fixtures/conftest_automotive.py.

Markers registered:
  vtc  — Verification Test Case (VT-NN)
  sim  — Phase 1 simulation test (no hardware required)
  slow — Test involves real timer delays; skipped unless --runslow is passed
  hw   — Phase 2 hardware test (requires --hardware flag)
"""
import pytest

from sim.ecu_state import ECUState, LifecycleState
from sim.nvm import NvM
from sim.dem import DEM
from sim.hsm import HSM
from sim.cryif import CryIf
from sim.csm import CSM
from sim.config import (
    HSM_KEY_ID_OEM_ROOT,
    HSM_KEY_ID_OEM_SIGNING,
    HSM_KEY_ID_BOOTLOADER,
    HSM_KEY_ID_DEBUG_AUTH,
    FIRMWARE_VERSION_FLOOR_APP,
    BOOT_STAGE_BOOTLOADER,
    BOOT_STAGE_APPLICATION,
)

from sim.security_logger import SecurityLogger
from sim.crypto_provider import CryptoProvider
from sim.trust_anchor_manager import TrustAnchorManager
from sim.version_manager import VersionManager
from sim.manifest_validator import ManifestValidator
from sim.recovery_manager import RecoveryManager
from sim.update_manager import UpdateManager
from sim.debug_manager import DebugManager
from sim.attestation_service import AttestationService
from sim.boot_rom import BootROM
from sim.secure_boot_manager import SecureBootManager


# ---------------------------------------------------------------------------
# CLI options and marker registration
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    parser.addoption(
        "--runslow",
        action="store_true",
        default=False,
        help="Run slow tests (timer/delay-dependent)",
    )
    parser.addoption(
        "--hardware",
        action="store_true",
        default=False,
        help="Run against physical hardware (Phase 2)",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "vtc(id): Verification Test Case ID (VT-NN)")
    config.addinivalue_line("markers", "sim: Phase 1 simulation test (no hardware required)")
    config.addinivalue_line("markers", "slow: Test involves real timer delays")
    config.addinivalue_line("markers", "hw: Phase 2 hardware test (requires --hardware flag)")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--runslow"):
        skip_slow = pytest.mark.skip(reason="Pass --runslow to run timer-dependent tests")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)


# ---------------------------------------------------------------------------
# Infrastructure fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_nvm_path(tmp_path):
    return str(tmp_path / "nvm_store.json")


@pytest.fixture
def nvm(tmp_nvm_path):
    return NvM(path=tmp_nvm_path)


@pytest.fixture
def dem():
    return DEM()


@pytest.fixture
def hsm():
    h = HSM()
    h.generate_key_pair(HSM_KEY_ID_OEM_ROOT)
    h.generate_key_pair(HSM_KEY_ID_OEM_SIGNING)
    h.generate_key_pair(HSM_KEY_ID_BOOTLOADER)
    h.generate_key_pair(HSM_KEY_ID_DEBUG_AUTH)
    return h


@pytest.fixture
def cryif(hsm):
    return CryIf(hsm=hsm)


@pytest.fixture
def csm(cryif):
    return CSM(cryif=cryif)


@pytest.fixture
def ecu_state():
    return ECUState()


@pytest.fixture
def production_ecu_state():
    """ECUState in PRODUCTION lifecycle with secure boot enabled."""
    s = ECUState()
    s.lifecycle = LifecycleState.PRODUCTION
    s.secure_boot_enabled = True
    return s


# ---------------------------------------------------------------------------
# Domain fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def security_logger(dem, nvm):
    return SecurityLogger(dem=dem, nvm=nvm)


@pytest.fixture
def crypto_provider(csm):
    return CryptoProvider(csm=csm)


@pytest.fixture
def trust_anchor_manager(hsm, security_logger):
    return TrustAnchorManager(hsm=hsm, sl=security_logger)


@pytest.fixture
def version_manager(nvm, security_logger):
    return VersionManager(nvm=nvm, sl=security_logger)


@pytest.fixture
def manifest_validator():
    return ManifestValidator()


@pytest.fixture
def recovery_manager(crypto_provider, security_logger, nvm, ecu_state):
    return RecoveryManager(cp=crypto_provider, sl=security_logger, nvm=nvm, ecu=ecu_state)


@pytest.fixture
def update_manager(crypto_provider, version_manager, security_logger, nvm):
    return UpdateManager(cp=crypto_provider, vm=version_manager, sl=security_logger, nvm=nvm)


@pytest.fixture
def debug_manager(ecu_state, nvm, hsm, security_logger):
    return DebugManager(ecu=ecu_state, nvm=nvm, hsm=hsm, sl=security_logger)


@pytest.fixture
def debug_manager_production(production_ecu_state, nvm, hsm, security_logger):
    return DebugManager(ecu=production_ecu_state, nvm=nvm, hsm=hsm, sl=security_logger)


@pytest.fixture
def attestation_service(csm, nvm, security_logger):
    return AttestationService(csm=csm, nvm=nvm, sl=security_logger)


@pytest.fixture
def boot_rom(
    trust_anchor_manager, crypto_provider, manifest_validator,
    version_manager, security_logger, ecu_state, nvm,
):
    return BootROM(
        tam=trust_anchor_manager, cp=crypto_provider, mv=manifest_validator,
        vm=version_manager, sl=security_logger, ecu=ecu_state, nvm=nvm,
    )


@pytest.fixture
def secure_boot_manager(
    crypto_provider, manifest_validator, version_manager, recovery_manager,
    security_logger, attestation_service, ecu_state, nvm,
):
    return SecureBootManager(
        cp=crypto_provider, mv=manifest_validator, vm=version_manager,
        rm=recovery_manager, sl=security_logger, att=attestation_service,
        ecu=ecu_state, nvm=nvm,
    )


# ---------------------------------------------------------------------------
# Firmware image fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_bootloader_image(hsm):
    """Valid signed bootloader at version floor + 1."""
    image_data = b"BOOTLOADER_IMAGE_V2_VALID_PAYLOAD_32BYTES__"
    signature = hsm.sign(HSM_KEY_ID_OEM_SIGNING, image_data)
    version = FIRMWARE_VERSION_FLOOR_APP + 1
    return image_data, signature, version


@pytest.fixture
def valid_application_image(hsm):
    """Valid signed application at version floor + 1."""
    image_data = b"APPLICATION_IMAGE_V2_VALID_PAYLOAD_32BYTES_"
    signature = hsm.sign(HSM_KEY_ID_OEM_SIGNING, image_data)
    version = FIRMWARE_VERSION_FLOOR_APP + 1
    return image_data, signature, version


@pytest.fixture
def tampered_bootloader_image(hsm):
    """Bootloader modified after signing — signature invalid."""
    original = b"BOOTLOADER_IMAGE_V2_VALID_PAYLOAD_32BYTES__"
    signature = hsm.sign(HSM_KEY_ID_OEM_SIGNING, original)
    tampered = original[:-4] + b"\xDE\xAD\xBE\xEF"
    return tampered, signature, FIRMWARE_VERSION_FLOOR_APP + 1


@pytest.fixture
def tampered_application_image(hsm):
    """Application modified after signing — signature invalid."""
    original = b"APPLICATION_IMAGE_V2_VALID_PAYLOAD_32BYTES_"
    signature = hsm.sign(HSM_KEY_ID_OEM_SIGNING, original)
    tampered = original[:-4] + b"\xDE\xAD\xBE\xEF"
    return tampered, signature, FIRMWARE_VERSION_FLOOR_APP + 1


@pytest.fixture
def downgrade_bootloader_image(hsm):
    """Validly signed bootloader at version below NvM floor."""
    image_data = b"BOOTLOADER_IMAGE_V0_OLD_PAYLOAD_32BYTES____"
    signature = hsm.sign(HSM_KEY_ID_OEM_SIGNING, image_data)
    version = max(0, FIRMWARE_VERSION_FLOOR_APP - 1)
    return image_data, signature, version


@pytest.fixture
def downgrade_application_image(hsm):
    """Validly signed application at version below NvM floor."""
    image_data = b"APPLICATION_IMAGE_V0_OLD_PAYLOAD_32BYTES___"
    signature = hsm.sign(HSM_KEY_ID_OEM_SIGNING, image_data)
    version = max(0, FIRMWARE_VERSION_FLOOR_APP - 1)
    return image_data, signature, version


@pytest.fixture
def valid_manifest_bytes(hsm):
    """Valid JSON manifest bytes for a bootloader image."""
    import json, base64
    image_data = b"BOOTLOADER_IMAGE_V2_VALID_PAYLOAD_32BYTES__"
    from sim.hsm import HSM as _HSM
    from sim.config import APPROVED_HASH_ALGORITHM
    from cryptography.hazmat.primitives import hashes
    digest_obj = hashes.Hash(hashes.SHA256())
    digest_obj.update(image_data)
    img_hash = digest_obj.finalize()
    sig = hsm.sign(HSM_KEY_ID_OEM_SIGNING, image_data)
    manifest = {
        "image_hash": base64.b64encode(img_hash).decode(),
        "signature": base64.b64encode(sig).decode(),
        "version": FIRMWARE_VERSION_FLOOR_APP + 1,
        "component": "BOOTLOADER",
        "key_id": HSM_KEY_ID_OEM_SIGNING,
        "not_before": "2020-01-01T00:00:00Z",
        "not_after": "2099-12-31T23:59:59Z",
    }
    return json.dumps(manifest).encode()


@pytest.fixture
def invalid_manifest_bytes():
    """Malformed JSON manifest bytes."""
    return b"{ this is not valid json !!!"


@pytest.fixture
def manifest_missing_field_bytes(hsm):
    """Valid JSON but missing required 'signature' field."""
    import json, base64
    manifest = {
        "image_hash": base64.b64encode(b"\x00" * 32).decode(),
        "version": 2,
        "component": "BOOTLOADER",
        "key_id": HSM_KEY_ID_OEM_SIGNING,
        # 'signature' intentionally omitted
    }
    return json.dumps(manifest).encode()
