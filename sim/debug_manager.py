"""DebugManager — JTAG/SWD lock enforcement and secure boot enable protection.

In PRODUCTION and EOL lifecycle: debug interface locked; gate_debug_access()
requires a valid ECDSA credential signed by the debug-auth key.
In DEVELOPMENT lifecycle: debug interface open (no credential required).

check_debug_lock_on_startup() is called automatically in __init__ and can be
called again idempotently (e.g. from tests).

SWR-C-011  Verify debug interface lock status during startup
SR-009     Secure boot enable state hardware-protected across resets
SR-014     Unauthorized debug access prevented in production
"""
from __future__ import annotations

from sim.config import (
    HSM_KEY_ID_DEBUG_AUTH,
    NVM_KEY_DEBUG_LOCKED,
    NVM_KEY_SECURE_BOOT_ENABLED,
)
from sim.ecu_state import LifecycleState

_DEBUG_AUTH_CHALLENGE = b"debug_access_request_v1"


class DebugManagerError(Exception):
    pass


class DebugManager:
    """Enforces debug interface policy and protects secure-boot enable state."""

    def __init__(self, ecu: object, nvm: object, hsm: object, sl: object) -> None:
        self._ecu = ecu
        self._nvm = nvm
        self._hsm = hsm
        self._sl = sl
        self.check_debug_lock_on_startup()

    def check_debug_lock_on_startup(self) -> None:
        """Enforce debug lock and secure-boot enable protection on startup.

        - PRODUCTION / EOL lifecycle → lock debug interface.
        - DEVELOPMENT lifecycle → debug interface open.
        - If secure_boot is False in PRODUCTION → tamper event + re-enforce.
        """
        is_restricted = self._ecu.lifecycle in (
            LifecycleState.PRODUCTION, LifecycleState.EOL
        )

        if is_restricted:
            self._ecu.debug_locked = True
            nvm_sb = self._nvm.read(NVM_KEY_SECURE_BOOT_ENABLED)
            if nvm_sb is False:
                self._sl.log_tamper_event(
                    "SECURE_BOOT_DISABLED_IN_PRODUCTION",
                    {"lifecycle": self._ecu.lifecycle.value},
                )
                self._ecu.secure_boot_enabled = True
                self._nvm.write(NVM_KEY_SECURE_BOOT_ENABLED, True)
                self._nvm.write(NVM_KEY_DEBUG_LOCKED, True)
                raise DebugManagerError("secure_boot_disabled_in_production")
        else:
            self._ecu.debug_locked = False

        self._nvm.write(NVM_KEY_DEBUG_LOCKED, self._ecu.debug_locked)
        self._nvm.write(NVM_KEY_SECURE_BOOT_ENABLED, self._ecu.secure_boot_enabled)
        self._sl.log_boot_event(
            "DEBUG_LOCK_CHECKED", {"locked": self._ecu.debug_locked}
        )

    def is_debug_locked(self) -> bool:
        """Return True if the debug interface is currently locked."""
        return self._ecu.debug_locked

    def is_secure_boot_enabled(self) -> bool:
        """Return True if secure boot is enabled (models hardware fuse in sim)."""
        return self._ecu.secure_boot_enabled

    def gate_debug_access(self, credential: bytes) -> bool:
        """Grant or deny debug access based on lifecycle and credential validity.

        In DEVELOPMENT lifecycle any call returns True (open debug).
        In PRODUCTION / EOL the credential must be a valid ECDSA signature of
        the canonical debug-auth challenge under HSM_KEY_ID_DEBUG_AUTH.

        Args:
            credential: DER-encoded ECDSA signature to verify.

        Returns:
            True if access is granted; False if denied.
        """
        if not self._ecu.debug_locked:
            return True

        try:
            valid = self._hsm.verify(
                HSM_KEY_ID_DEBUG_AUTH, _DEBUG_AUTH_CHALLENGE, credential
            )
        except Exception:
            valid = False

        if not valid:
            self._sl.log_verification_failure(
                "DEBUG_ACCESS", "invalid_credential"
            )
        return valid

    def get_status(self) -> dict:
        """Return current debug manager status.

        Returns:
            Dict with debug_locked, secure_boot_enabled, and lifecycle.
        """
        return {
            "debug_locked": self._ecu.debug_locked,
            "secure_boot_enabled": self._ecu.secure_boot_enabled,
            "lifecycle": self._ecu.lifecycle.value,
        }
