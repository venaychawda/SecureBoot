"""RecoveryManager — authenticated recovery mode.

Only OEM-signed images are accepted for recovery flashing.
Unsigned or tampered images are rejected and the event logged.

SWR-C-009  Initiate authenticated recovery on verification failure
SR-017     Only authenticated recovery flashing accepted
"""
from __future__ import annotations

from sim.config import HSM_KEY_ID_OEM_SIGNING
from sim.ecu_state import BootPhase


class RecoveryError(Exception):
    pass


_NVM_KEY_ACTIVE_APP = "active_application_image"


class RecoveryManager:
    """Manages entry into recovery mode and authenticated recovery image flashing."""

    def __init__(self, cp: object, sl: object, nvm: object, ecu: object) -> None:
        self._cp = cp
        self._sl = sl
        self._nvm = nvm
        self._ecu = ecu

    def enter_recovery_mode(self, reason: str) -> None:
        """Transition the ECU to SAFE_STATE and log the recovery entry.

        Args:
            reason: Short string describing why recovery was triggered.
        """
        self._ecu.transition(BootPhase.SAFE_STATE, reason)
        self._sl.log_boot_event("RECOVERY_MODE_ENTERED", {"reason": reason})

    def verify_recovery_image(self, image: bytes, signature: bytes) -> bool:
        """Check that a recovery image carries a valid OEM signature.

        Args:
            image: Raw firmware binary.
            signature: DER-encoded ECDSA signature from OEM signing key.

        Returns:
            True if valid; False otherwise.
        """
        result = self._cp.verify_image_signature(image, signature, HSM_KEY_ID_OEM_SIGNING)
        if not result:
            self._sl.log_verification_failure("RECOVERY", "signature_invalid")
        return result

    def execute_recovery_flash(self, image: bytes, signature: bytes) -> bool:
        """Authenticate and atomically flash a recovery image.

        Args:
            image: Raw firmware binary.
            signature: DER-encoded ECDSA signature.

        Returns:
            True on successful flash; False if authentication fails.
        """
        if not self.verify_recovery_image(image, signature):
            self._sl.log_tamper_event("RECOVERY_FLASH_REJECTED")
            return False
        self._nvm.write(
            _NVM_KEY_ACTIVE_APP,
            {"image": image.hex(), "sig": signature.hex(), "version": 1},
        )
        self._sl.log_boot_event("RECOVERY_FLASH_SUCCESS")
        return True

    def get_recovery_status(self) -> dict:
        """Return current recovery status.

        Returns:
            Dict with boot_phase and last_failure_reason.
        """
        return {
            "boot_phase": self._ecu.boot_phase.value,
            "last_failure": self._ecu.last_failure_reason,
        }
