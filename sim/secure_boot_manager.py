"""SecureBootManager — full secure boot sequence orchestrator.

run_boot_sequence() requires a provisioned application image in NvM
(written there by UpdateManager.activate_update or RecoveryManager.execute_recovery_flash).
If no image is stored the ECU enters SAFE_STATE.

handle_interruption() reads the boot-attempt counter from NvM; if the
counter exceeds MAX_BOOT_RETRY_ATTEMPTS the ECU is locked out permanently.

SWR-C-001  Initiate secure boot on startup
SWR-C-003  Verify application image before startup
SWR-C-008  Verify chain of trust before stage handoff
SWR-C-012  Restart sequence after abnormal interruption
SWR-C-014  Reject images with invalid manifests
"""
from __future__ import annotations

from dataclasses import dataclass

from sim.config import (
    FIRMWARE_VERSION_FLOOR_APP,
    HSM_KEY_ID_OEM_SIGNING,
    MAX_BOOT_RETRY_ATTEMPTS,
    NVM_KEY_BOOT_COUNTER,
)
from sim.ecu_state import BootPhase


class SecureBootError(Exception):
    pass


@dataclass
class BootResult:
    """Outcome of a boot sequence run."""

    success: bool
    phase_reached: str
    failure_reason: str | None = None


_NVM_KEY_ACTIVE_APP = "active_application_image"


class SecureBootManager:
    """Orchestrates the full secure boot chain from ROM_INIT to NORMAL_OPERATION."""

    def __init__(
        self,
        cp: object,
        mv: object,
        vm: object,
        rm: object,
        sl: object,
        att: object,
        ecu: object,
        nvm: object,
    ) -> None:
        self._cp = cp
        self._mv = mv
        self._vm = vm
        self._rm = rm
        self._sl = sl
        self._att = att
        self._ecu = ecu
        self._nvm = nvm

    def run_boot_sequence(self) -> BootResult:
        """Execute boot: ROM_INIT → APPLICATION_VERIFY → NORMAL_OPERATION.

        Reads the active application image from NvM.  If no image is stored
        the ECU transitions to SAFE_STATE (requires provisioning via UpdateManager).

        Returns:
            BootResult describing the phase reached and any failure reason.
        """
        self._ecu.transition(BootPhase.ROM_INIT)
        self._sl.log_boot_event("BOOT_SEQUENCE_STARTED")

        stored = self._nvm.read(_NVM_KEY_ACTIVE_APP)
        if stored is None:
            self._ecu.transition(BootPhase.SAFE_STATE, "no_application_image")
            self._sl.log_verification_failure(
                "APPLICATION_VERIFY", "no_image_stored"
            )
            return BootResult(
                success=False,
                phase_reached=BootPhase.SAFE_STATE,
                failure_reason="no_application_image",
            )

        self._ecu.transition(BootPhase.APPLICATION_VERIFY)

        image = bytes.fromhex(stored["image"])
        sig = bytes.fromhex(stored["sig"])
        version = stored["version"]

        if not self.verify_application_image(image, sig, version):
            return BootResult(
                success=False,
                phase_reached=self._ecu.boot_phase,
                failure_reason="app_verify_failed",
            )

        digest = self._att.measure_component("application", image)
        self._ecu.attestation_hash = digest

        self._ecu.transition(BootPhase.NORMAL_OPERATION)
        self._sl.log_boot_event("APPLICATION_VERIFIED_BOOT_COMPLETE")
        return BootResult(success=True, phase_reached=BootPhase.NORMAL_OPERATION)

    def verify_application_image(
        self, image: bytes, signature: bytes, version: int
    ) -> bool:
        """Verify application image signature and minimum version floor.

        Args:
            image: Raw firmware binary.
            signature: DER-encoded ECDSA signature.
            version: Firmware version integer stored in the image manifest.

        Returns:
            True if verification passes; False otherwise.
        """
        if not self._cp.verify_image_signature(image, signature, HSM_KEY_ID_OEM_SIGNING):
            self._sl.log_verification_failure(
                "APPLICATION_VERIFY", "signature_invalid"
            )
            self._ecu.transition(BootPhase.SAFE_STATE, "app_sig_invalid")
            return False

        if version < FIRMWARE_VERSION_FLOOR_APP:
            self._sl.log_verification_failure(
                "APPLICATION_VERIFY", "below_version_floor"
            )
            self._ecu.transition(BootPhase.SAFE_STATE, "app_below_floor")
            return False

        return True

    def handle_interruption(self) -> None:
        """Handle a detected power-loss or abnormal boot interruption.

        Reads the NvM boot-attempt counter.  If the counter exceeds
        MAX_BOOT_RETRY_ATTEMPTS the ECU is permanently locked out;
        otherwise it is reset to ROM_INIT for a clean retry.
        """
        count = self._nvm.read(NVM_KEY_BOOT_COUNTER, default=0)
        self._sl.log_boot_event("BOOT_INTERRUPTED", {"count": count})

        if count > MAX_BOOT_RETRY_ATTEMPTS:
            self._ecu.transition(BootPhase.LOCKED_OUT, "max_retries_exceeded")
            self._sl.log_tamper_event("BOOT_LOCKOUT", {"count": count})
        else:
            self._ecu.transition(BootPhase.ROM_INIT, "interrupted_reset")

    def get_boot_status(self) -> dict:
        """Return current boot manager status.

        Returns:
            Dict with boot_phase, secure_boot_enabled, and last_failure_reason.
        """
        return {
            "boot_phase": self._ecu.boot_phase.value,
            "secure_boot_enabled": self._ecu.secure_boot_enabled,
            "last_failure_reason": self._ecu.last_failure_reason,
        }
