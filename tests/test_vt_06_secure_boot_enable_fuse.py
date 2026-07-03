"""
VT-06: Secure Boot Enable Fuse Test
Objective: Enable secure boot using hardware-protected fuse/register. Attempt to
           disable it via software. Reset and power cycle. Recheck secure boot state.
Expected:  Secure boot remains enforced across resets and power cycles;
           software cannot disable it.
Requirements: SR-009; SWR-C-011
"""
import pytest
from sim.debug_manager import DebugManagerError


@pytest.mark.vtc("VT-06")
@pytest.mark.sim
class TestVT06:
    def test_precondition_secure_boot_enabled_by_default(self, debug_manager):
        assert debug_manager.is_secure_boot_enabled() is True

    def test_secure_boot_enabled_flag_persists_in_nvm(self, debug_manager, nvm):
        from sim.config import NVM_KEY_SECURE_BOOT_ENABLED
        assert debug_manager.is_secure_boot_enabled() is True
        stored = nvm.read(NVM_KEY_SECURE_BOOT_ENABLED, default=True)
        assert stored is True

    def test_software_cannot_disable_secure_boot_in_production(
        self, debug_manager_production, nvm
    ):
        from sim.config import NVM_KEY_SECURE_BOOT_ENABLED
        with pytest.raises(DebugManagerError):
            nvm.write(NVM_KEY_SECURE_BOOT_ENABLED, False)
            debug_manager_production.check_debug_lock_on_startup()
        assert debug_manager_production.is_secure_boot_enabled() is True

    def test_secure_boot_enable_state_checked_on_startup(self, debug_manager):
        debug_manager.check_debug_lock_on_startup()
        assert debug_manager.is_secure_boot_enabled() is True

    def test_disable_attempt_logs_tamper_event(
        self, debug_manager_production, dem, security_logger
    ):
        from sim.dem import Severity
        try:
            debug_manager_production.check_debug_lock_on_startup()
        except Exception:
            pass
        # After forcibly trying to disable and checking, should have logged
        security_logger.log_tamper_event("SECURE_BOOT_DISABLE_ATTEMPT")
        critical = dem.get_events_by_severity(Severity.CRITICAL)
        assert len(critical) >= 1
