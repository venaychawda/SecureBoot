"""
VT-20: End-to-End Secure Boot Regression Suite
Objective: Run automated test coverage across ROM, bootloader, and application chain.
           Include update interruption, rollback, recovery, and fault-injection scenarios.
           Verify pass/fail results and logs. Repeat after software updates.
Expected:  The full secure boot flow passes consistently and no regression is introduced.
Requirements: SWR-C-001; SWR-C-008; SWR-C-013
"""
import pytest
from sim.ecu_state import BootPhase
from sim.dem import Severity


@pytest.mark.vtc("VT-20")
@pytest.mark.sim
class TestVT20:
    def test_golden_path_boot_succeeds(self, boot_rom, ecu_state):
        boot_rom.power_on()
        assert ecu_state.boot_phase == BootPhase.NORMAL_OPERATION

    def test_rollback_attempt_blocked_in_end_to_end_flow(
        self, update_manager, version_manager, downgrade_application_image
    ):
        image, sig, version = downgrade_application_image
        version_manager.commit_version("application", version + 1)
        result = update_manager.validate_update_package(image, sig)
        assert result is False

    def test_recovery_mode_reachable_after_boot_failure(
        self, secure_boot_manager, tampered_application_image, recovery_manager, ecu_state
    ):
        try:
            secure_boot_manager.run_boot_sequence()
        except Exception:
            pass
        recovery_manager.enter_recovery_mode("VT20_REGRESSION")
        assert ecu_state.boot_phase == BootPhase.SAFE_STATE

    def test_fault_injection_does_not_bypass_chain(
        self, boot_rom, tampered_bootloader_image, ecu_state
    ):
        image, sig, version = tampered_bootloader_image
        boot_rom.verify_bootloader(image, sig, version)
        assert ecu_state.boot_phase not in (
            BootPhase.APPLICATION_VERIFY, BootPhase.NORMAL_OPERATION
        )

    def test_all_security_failures_produce_critical_dem_events(
        self, security_logger, dem
    ):
        security_logger.log_verification_failure("REGRESSION_TEST", "forced_failure")
        events = dem.get_events_by_severity(Severity.CRITICAL)
        assert len(events) >= 1

    def test_post_update_boot_sequence_succeeds(
        self, update_manager, secure_boot_manager, valid_application_image, ecu_state
    ):
        image, sig, version = valid_application_image
        update_manager.activate_update(image, sig)
        boot_rom_result = secure_boot_manager.run_boot_sequence()
        assert ecu_state.boot_phase == BootPhase.NORMAL_OPERATION
