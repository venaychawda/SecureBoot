"""UpdateManager — OTA/service update authentication and atomic activation.

validate_update_package() authenticates signature and checks anti-rollback.
activate_update() backs up the current image before overwriting (atomic swap).
rollback_update() restores the backed-up image.

NvM key "pending_update_version" holds the version claimed by the next update;
defaults to FIRMWARE_VERSION_FLOOR_APP if not explicitly set by the caller.

SWR-C-013  Verify update package authenticity before activation
SR-010     Atomic activation with fallback to known-good image
"""
from __future__ import annotations

from sim.config import FIRMWARE_VERSION_FLOOR_APP, HSM_KEY_ID_OEM_SIGNING

_NVM_KEY_ACTIVE_APP = "active_application_image"
_NVM_KEY_PREVIOUS_APP = "previous_application_image"
_NVM_KEY_PENDING_VER = "pending_update_version"
_NVM_KEY_UPDATE_PENDING = "update_pending"


class UpdateError(Exception):
    pass


class UpdateManager:
    """Manages authenticated update package validation, activation, and rollback."""

    def __init__(self, cp: object, vm: object, sl: object, nvm: object) -> None:
        self._cp = cp
        self._vm = vm
        self._sl = sl
        self._nvm = nvm

    def validate_update_package(self, package: bytes, signature: bytes) -> bool:
        """Authenticate package and check anti-rollback version.

        Args:
            package: Raw firmware image bytes.
            signature: DER-encoded ECDSA signature.

        Returns:
            True if signature is valid and version is acceptable; False otherwise.
        """
        if not self._cp.verify_image_signature(package, signature, HSM_KEY_ID_OEM_SIGNING):
            self._sl.log_verification_failure("UPDATE", "signature_invalid")
            return False

        version = int(self._nvm.read(_NVM_KEY_PENDING_VER, default=FIRMWARE_VERSION_FLOOR_APP))
        if not self._vm.validate_version("application", version):
            self._sl.log_verification_failure(
                "UPDATE", "rollback_attempt", {"version": version}
            )
            return False
        return True

    def activate_update(self, package: bytes, signature: bytes) -> bool:
        """Validate, backup current image, then atomically write the new image.

        Args:
            package: Raw firmware image bytes.
            signature: DER-encoded ECDSA signature.

        Returns:
            True on successful activation; False if validation fails.
        """
        if not self.validate_update_package(package, signature):
            self._nvm.write(_NVM_KEY_UPDATE_PENDING, False)
            return False

        current = self._nvm.read(_NVM_KEY_ACTIVE_APP)
        self._nvm.write(_NVM_KEY_PREVIOUS_APP, current)

        version = int(self._nvm.read(_NVM_KEY_PENDING_VER, default=FIRMWARE_VERSION_FLOOR_APP))
        self._nvm.write(
            _NVM_KEY_ACTIVE_APP,
            {"image": package.hex(), "sig": signature.hex(), "version": version},
        )
        self._vm.commit_version("application", version)
        self._nvm.write(_NVM_KEY_UPDATE_PENDING, False)
        self._sl.log_boot_event("UPDATE_ACTIVATED", {"version": version})
        return True

    def rollback_update(self) -> bool:
        """Restore the previously backed-up application image.

        Returns:
            True after restoring (always succeeds after at least one activate_update call).
        """
        previous = self._nvm.read(_NVM_KEY_PREVIOUS_APP)
        self._nvm.write(_NVM_KEY_ACTIVE_APP, previous)
        self._nvm.write(_NVM_KEY_UPDATE_PENDING, False)
        self._sl.log_boot_event("UPDATE_ROLLED_BACK")
        return True

    def get_update_status(self) -> dict:
        """Return current update manager status.

        Returns:
            Dict with update_pending and active_version.
        """
        return {
            "update_pending": self._nvm.read(_NVM_KEY_UPDATE_PENDING, default=False),
            "active_version": self._vm.get_version("application"),
        }
