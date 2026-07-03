"""
VT-01: Bootloader Signature Verification Test
Objective: Flash a valid signed bootloader and confirm normal startup.
           Replace with a modified/invalidly signed image.
           Power cycle the ECU. Observe boot ROM behavior and logs.
Expected:  Boot ROM rejects the invalid bootloader, prevents execution,
           enters safe/recovery state with a diagnostic/security log.
Requirements: SR-001; SR-003; SR-007; SWR-C-001; SWR-C-002; SWR-C-008
"""
import pytest
from sim.ecu_state import BootPhase


@pytest.mark.vtc("VT-01")
@pytest.mark.sim
class TestVT01:
    def test_precondition_hsm_has_oem_key(self, hsm):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        pem = hsm.get_public_key_pem(HSM_KEY_ID_OEM_SIGNING)
        assert pem is not None and len(pem) > 0

    def test_valid_bootloader_accepted(self, boot_rom, valid_bootloader_image):
        image, sig, version = valid_bootloader_image
        result = boot_rom.verify_bootloader(image, sig, version)
        assert result is True

    def test_tampered_bootloader_rejected(self, boot_rom, tampered_bootloader_image):
        image, sig, version = tampered_bootloader_image
        result = boot_rom.verify_bootloader(image, sig, version)
        assert result is False

    def test_tampered_boot_transitions_to_safe_state(
        self, boot_rom, tampered_bootloader_image, ecu_state
    ):
        image, sig, version = tampered_bootloader_image
        boot_rom.verify_bootloader(image, sig, version)
        assert ecu_state.boot_phase in (BootPhase.SAFE_STATE, BootPhase.RECOVERY_MODE)

    def test_tampered_boot_logs_critical_dem_event(
        self, boot_rom, tampered_bootloader_image, dem
    ):
        from sim.dem import Severity
        image, sig, version = tampered_bootloader_image
        boot_rom.verify_bootloader(image, sig, version)
        critical = dem.get_events_by_severity(Severity.CRITICAL)
        assert len(critical) >= 1

    def test_power_on_full_sequence_valid_image(self, boot_rom):
        result = boot_rom.power_on()
        assert result.success is True
        assert result.failure_reason is None
