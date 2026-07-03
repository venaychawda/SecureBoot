"""
VT-11: Recovery Mode Authentication Test
Objective: Enter recovery/service mode. Attempt to flash an unsigned or tampered image.
           Try a properly signed image afterward. Observe acceptance behavior.
Expected:  Unsigned/tampered images are rejected; only authenticated recovery
           flashing is accepted.
Requirements: SR-017; SWR-C-009
"""
import pytest
from sim.ecu_state import BootPhase
from sim.recovery_manager import RecoveryError


@pytest.mark.vtc("VT-11")
@pytest.mark.sim
class TestVT11:
    def test_precondition_enter_recovery_mode(self, recovery_manager, ecu_state):
        recovery_manager.enter_recovery_mode("VT11_TEST")
        assert ecu_state.boot_phase == BootPhase.SAFE_STATE

    def test_unsigned_recovery_image_rejected(
        self, recovery_manager, valid_application_image
    ):
        image, _, _ = valid_application_image
        recovery_manager.enter_recovery_mode("VT11_TEST")
        result = recovery_manager.verify_recovery_image(image, b"\x00" * 64)
        assert result is False

    def test_tampered_recovery_image_rejected(
        self, recovery_manager, tampered_application_image
    ):
        image, sig, _ = tampered_application_image
        recovery_manager.enter_recovery_mode("VT11_TEST")
        result = recovery_manager.verify_recovery_image(image, sig)
        assert result is False

    def test_valid_recovery_image_accepted(
        self, recovery_manager, valid_application_image
    ):
        image, sig, _ = valid_application_image
        recovery_manager.enter_recovery_mode("VT11_TEST")
        result = recovery_manager.verify_recovery_image(image, sig)
        assert result is True

    def test_authenticated_recovery_flash_succeeds(
        self, recovery_manager, valid_application_image
    ):
        image, sig, _ = valid_application_image
        recovery_manager.enter_recovery_mode("VT11_TEST")
        result = recovery_manager.execute_recovery_flash(image, sig)
        assert result is True

    def test_rejected_recovery_logs_critical_event(
        self, recovery_manager, valid_application_image, dem
    ):
        from sim.dem import Severity
        image, _, _ = valid_application_image
        recovery_manager.enter_recovery_mode("VT11_TEST")
        recovery_manager.execute_recovery_flash(image, b"\x00" * 64)
        critical = dem.get_events_by_severity(Severity.CRITICAL)
        assert len(critical) >= 1
