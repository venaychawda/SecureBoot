"""Central ECU state machine shared by all sim modules."""
from enum import Enum
from typing import Optional


class BootPhase(str, Enum):
    POWER_OFF = "POWER_OFF"
    ROM_INIT = "ROM_INIT"
    BOOTLOADER_VERIFY = "BOOTLOADER_VERIFY"
    APPLICATION_VERIFY = "APPLICATION_VERIFY"
    NORMAL_OPERATION = "NORMAL_OPERATION"
    RECOVERY_MODE = "RECOVERY_MODE"
    SAFE_STATE = "SAFE_STATE"
    LOCKED_OUT = "LOCKED_OUT"


class LifecycleState(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    PRODUCTION = "PRODUCTION"
    EOL = "EOL"


class ECUState:
    """Central mutable ECU state. Single instance shared across all modules."""

    def __init__(self) -> None:
        self.boot_phase: BootPhase = BootPhase.POWER_OFF
        self.lifecycle: LifecycleState = LifecycleState.DEVELOPMENT
        self.secure_boot_enabled: bool = True
        self.debug_locked: bool = False
        self.boot_attempt_count: int = 0
        self.last_failure_reason: Optional[str] = None
        self.attestation_hash: Optional[bytes] = None

    def transition(self, new_phase: BootPhase, reason: str = "") -> None:
        """Transition to a new boot phase."""
        self.boot_phase = new_phase
        if new_phase in (BootPhase.SAFE_STATE, BootPhase.RECOVERY_MODE, BootPhase.LOCKED_OUT):
            self.last_failure_reason = reason

    def to_dict(self) -> dict:
        return {
            "boot_phase": self.boot_phase.value,
            "lifecycle": self.lifecycle.value,
            "secure_boot_enabled": self.secure_boot_enabled,
            "debug_locked": self.debug_locked,
            "boot_attempt_count": self.boot_attempt_count,
            "last_failure_reason": self.last_failure_reason,
        }
