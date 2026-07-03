"""
VT-02: Application Signature Integrity Test
Objective: Flash a valid signed bootloader. Modify the application image or remove
           its signature. Reboot the ECU. Observe application verification and boot status.
Expected:  The bootloader rejects the application image and prevents execution
           of tampered or unsigned firmware.
Requirements: SR-004; SWR-C-003; SWR-C-014
"""
import pytest
from sim.ecu_state import BootPhase


@pytest.mark.vtc("VT-02")
@pytest.mark.sim
class TestVT02:
    def test_precondition_valid_app_is_signable(self, hsm, valid_application_image):
        image, sig, version = valid_application_image
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        assert hsm.verify(HSM_KEY_ID_OEM_SIGNING, image, sig) is True

    def test_valid_application_accepted(
        self, secure_boot_manager, valid_application_image
    ):
        image, sig, version = valid_application_image
        result = secure_boot_manager.verify_application_image(image, sig, version)
        assert result is True

    def test_tampered_application_rejected(
        self, secure_boot_manager, tampered_application_image
    ):
        image, sig, version = tampered_application_image
        result = secure_boot_manager.verify_application_image(image, sig, version)
        assert result is False

    def test_tampered_app_halts_before_execution(
        self, secure_boot_manager, tampered_application_image, ecu_state
    ):
        image, sig, version = tampered_application_image
        secure_boot_manager.verify_application_image(image, sig, version)
        assert ecu_state.boot_phase != BootPhase.NORMAL_OPERATION

    def test_tampered_app_logs_critical_event(
        self, secure_boot_manager, tampered_application_image, dem
    ):
        from sim.dem import Severity
        image, sig, version = tampered_application_image
        secure_boot_manager.verify_application_image(image, sig, version)
        critical = dem.get_events_by_severity(Severity.CRITICAL)
        assert len(critical) >= 1

    def test_unsigned_application_rejected(self, secure_boot_manager, valid_application_image):
        image, _, version = valid_application_image
        result = secure_boot_manager.verify_application_image(image, b"\x00" * 64, version)
        assert result is False
