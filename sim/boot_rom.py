"""Boot ROM simulator — immutable hardware root of trust.

power_on() simulates the factory ROM: verifies a stored bootloader from NvM
if one was provisioned, otherwise uses the implicit factory-provisioned image
(always valid in simulation).  verify_bootloader() explicitly checks a supplied
image/sig/version tuple and is called directly by verification-focused tests.

SWR-C-001  Initiate secure boot verification during ECU startup
SWR-C-002  Verify bootloader image before execution
SWR-C-008  Verify chain of trust before stage handoff
"""
from __future__ import annotations

from dataclasses import dataclass

from sim.config import (
    BOOT_STAGE_BOOTLOADER,
    BOOT_STAGE_ROM,
    HSM_KEY_ID_OEM_SIGNING,
    MAX_BOOT_RETRY_ATTEMPTS,
    NVM_KEY_BOOT_COUNTER,
)
from sim.ecu_state import BootPhase


class BootROMError(Exception):
    pass


@dataclass
class BootResult:
    """Returned by power_on() describing the outcome of the boot sequence."""

    success: bool
    phase_reached: str
    failure_reason: str | None = None


class BootROM:
    """Simulates the immutable Boot ROM: power-on sequence and BL image verification."""

    def __init__(
        self,
        tam: object,
        cp: object,
        mv: object,
        vm: object,
        sl: object,
        ecu: object,
        nvm: object,
    ) -> None:
        self._tam = tam
        self._cp = cp
        self._mv = mv
        self._vm = vm
        self._sl = sl
        self._ecu = ecu
        self._nvm = nvm

    def power_on(self) -> BootResult:
        """Execute the full power-on boot sequence.

        If a bootloader image is stored in NvM it is verified; otherwise the
        implicit factory ROM image is assumed valid (simulation only).
        On success the ECU advances to NORMAL_OPERATION.

        Returns:
            BootResult describing phase reached and any failure reason.
        """
        self._ecu.transition(BootPhase.ROM_INIT)
        self._ecu.boot_attempt_count += 1
        self._nvm.write(NVM_KEY_BOOT_COUNTER, self._ecu.boot_attempt_count)
        self._sl.log_boot_event(BOOT_STAGE_ROM)

        if self._ecu.boot_attempt_count > MAX_BOOT_RETRY_ATTEMPTS:
            self._ecu.transition(BootPhase.LOCKED_OUT, "max_retries_exceeded")
            return BootResult(
                success=False,
                phase_reached=BootPhase.LOCKED_OUT,
                failure_reason="max_retries_exceeded",
            )

        stored_bl = self._nvm.read("active_bootloader_image")
        if stored_bl is not None:
            img = bytes.fromhex(stored_bl["image"])
            sig = bytes.fromhex(stored_bl["sig"])
            ver = stored_bl["version"]
            if not self.verify_bootloader(img, sig, ver):
                return BootResult(
                    success=False,
                    phase_reached=self._ecu.boot_phase,
                    failure_reason="bootloader_verify_failed",
                )
        else:
            self._ecu.transition(BootPhase.BOOTLOADER_VERIFY)
            self._sl.log_boot_event("BOOTLOADER_FACTORY_VERIFIED")

        self._ecu.transition(BootPhase.APPLICATION_VERIFY)
        self._sl.log_boot_event(BOOT_STAGE_BOOTLOADER)
        self._ecu.transition(BootPhase.NORMAL_OPERATION)
        self._sl.log_boot_event("BOOT_COMPLETE")
        return BootResult(success=True, phase_reached=BootPhase.NORMAL_OPERATION)

    def verify_bootloader(self, image: bytes, signature: bytes, version: int) -> bool:
        """Explicitly verify a bootloader image/signature/version tuple.

        Transitions ECU to BOOTLOADER_VERIFY then SAFE_STATE on failure.

        Args:
            image: Raw bootloader binary.
            signature: DER-encoded ECDSA signature.
            version: Firmware version integer.

        Returns:
            True if verification passed; False on any failure.
        """
        self._ecu.transition(BootPhase.BOOTLOADER_VERIFY)

        if not self._vm.validate_version("bootloader", version):
            self._sl.log_verification_failure("BOOTLOADER", "version_rollback")
            self._ecu.transition(BootPhase.SAFE_STATE, "bootloader_version_rollback")
            return False

        if not self._cp.verify_image_signature(image, signature, HSM_KEY_ID_OEM_SIGNING):
            self._sl.log_verification_failure("BOOTLOADER", "signature_invalid")
            self._ecu.transition(BootPhase.SAFE_STATE, "bootloader_sig_invalid")
            return False

        self._sl.log_boot_event("BOOTLOADER_VERIFIED", {"version": version})
        return True

    def get_status(self) -> dict:
        """Return current boot ROM status.

        Returns:
            Dict with boot_phase and boot_attempt_count.
        """
        return {
            "boot_phase": self._ecu.boot_phase.value,
            "boot_attempt_count": self._ecu.boot_attempt_count,
        }
