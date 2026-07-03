"""VersionManager — anti-rollback and replay protection via monotonic counters.

Two NvM keys per component:
  NVM_KEY_ROLLBACK_COUNTER_*  — highest version ever committed (starts at 0).
  NVM_KEY_FIRMWARE_VERSION_*  — currently installed version (seeded to floor on init).

validate_version() checks strictly against the rollback counter.
get_version()      returns the installed firmware version (floor on fresh ECU).

SWR-C-006  Validate firmware version counters before image acceptance
SWR-C-007  Reject firmware images below the stored counter (rollback)
"""
from __future__ import annotations

from sim.config import (
    FIRMWARE_VERSION_FLOOR_APP,
    FIRMWARE_VERSION_FLOOR_BL,
    NVM_KEY_FIRMWARE_VERSION_APP,
    NVM_KEY_FIRMWARE_VERSION_BL,
    NVM_KEY_ROLLBACK_COUNTER_APP,
    NVM_KEY_ROLLBACK_COUNTER_BL,
)


class VersionError(Exception):
    pass


class VersionManager:
    """Manages firmware version floors and monotonic rollback counters in NvM."""

    def __init__(self, nvm: object, sl: object) -> None:
        self._nvm = nvm
        self._sl = sl
        if self._nvm.read(NVM_KEY_FIRMWARE_VERSION_BL) is None:
            self._nvm.write(NVM_KEY_FIRMWARE_VERSION_BL, FIRMWARE_VERSION_FLOOR_BL)
        if self._nvm.read(NVM_KEY_FIRMWARE_VERSION_APP) is None:
            self._nvm.write(NVM_KEY_FIRMWARE_VERSION_APP, FIRMWARE_VERSION_FLOOR_APP)

    def validate_version(self, component: str, version: int) -> bool:
        """Return True if version is strictly greater than the committed counter.

        Args:
            component: "bootloader" or "application".
            version: Candidate firmware version.

        Returns:
            True if acceptable; False if rollback or replay detected.
        """
        counter = self._nvm.read(self._counter_key(component), default=0)
        if version <= counter:
            self._sl.log_verification_failure(
                f"VERSION_{component.upper()}",
                "rollback_attempt",
                {"attempted": version, "current": counter},
            )
            return False
        return True

    def commit_version(self, component: str, version: int) -> None:
        """Ratchet NvM rollback counter and installed version to version.

        Args:
            component: "bootloader" or "application".
            version: Newly accepted firmware version.
        """
        self._nvm.write(self._counter_key(component), version)
        self._nvm.write(self._version_key(component), version)

    def get_version(self, component: str) -> int:
        """Return the currently installed firmware version for a component.

        Args:
            component: "bootloader" or "application".

        Returns:
            Currently stored version (equals floor on a fresh ECU).
        """
        floor = (
            FIRMWARE_VERSION_FLOOR_BL
            if component == "bootloader"
            else FIRMWARE_VERSION_FLOOR_APP
        )
        return int(self._nvm.read(self._version_key(component), default=floor))

    def is_rollback(self, component: str, version: int) -> bool:
        """Return True if version is strictly below the committed counter (true rollback).

        Note: same-version (replay) is NOT considered a rollback by this predicate;
        use validate_version() to block both rollbacks and replays.

        Args:
            component: "bootloader" or "application".
            version: Version to test.
        """
        counter = self._nvm.read(self._counter_key(component), default=0)
        return version < counter

    def _counter_key(self, component: str) -> str:
        return (
            NVM_KEY_ROLLBACK_COUNTER_BL
            if component == "bootloader"
            else NVM_KEY_ROLLBACK_COUNTER_APP
        )

    def _version_key(self, component: str) -> str:
        return (
            NVM_KEY_FIRMWARE_VERSION_BL
            if component == "bootloader"
            else NVM_KEY_FIRMWARE_VERSION_APP
        )
