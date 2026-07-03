"""
VT-14: Chain-of-Trust Continuity Test
Objective: Tamper with one boot stage component (bootloader or application).
           Power cycle the ECU. Observe stage-by-stage verification.
           Identify the failure point.
Expected:  Boot halts at the compromised stage; the next stage is not executed.
Requirements: SWR-C-002; SWR-C-003; SWR-C-008; SWR-C-014
"""
import pytest
from sim.ecu_state import BootPhase


@pytest.mark.vtc("VT-14")
@pytest.mark.sim
class TestVT14:
    def test_precondition_full_chain_boots_normally(self, boot_rom, ecu_state):
        boot_rom.power_on()
        assert ecu_state.boot_phase == BootPhase.NORMAL_OPERATION

    def test_tampered_bootloader_halts_at_boot_rom_stage(
        self, boot_rom, tampered_bootloader_image, ecu_state
    ):
        image, sig, version = tampered_bootloader_image
        boot_rom.verify_bootloader(image, sig, version)
        assert ecu_state.boot_phase not in (
            BootPhase.APPLICATION_VERIFY, BootPhase.NORMAL_OPERATION
        )

    def test_tampered_application_halts_at_application_stage(
        self, secure_boot_manager, tampered_application_image, ecu_state
    ):
        secure_boot_manager.run_boot_sequence()
        assert ecu_state.boot_phase != BootPhase.NORMAL_OPERATION

    def test_failure_in_chain_triggers_security_log(
        self, boot_rom, tampered_bootloader_image, security_logger, dem
    ):
        from sim.dem import Severity
        image, sig, version = tampered_bootloader_image
        boot_rom.verify_bootloader(image, sig, version)
        critical = dem.get_events_by_severity(Severity.CRITICAL)
        assert len(critical) >= 1

    def test_attestation_records_each_stage(
        self, attestation_service, valid_bootloader_image, valid_application_image
    ):
        bl_image, _, _ = valid_bootloader_image
        app_image, _, _ = valid_application_image
        attestation_service.measure_component("bootloader", bl_image)
        attestation_service.measure_component("application", app_image)
        measurements = attestation_service.get_measurements()
        assert "bootloader" in measurements
        assert "application" in measurements

    def test_attestation_report_covers_both_stages(
        self, attestation_service, valid_bootloader_image, valid_application_image
    ):
        bl_image, _, _ = valid_bootloader_image
        app_image, _, _ = valid_application_image
        attestation_service.measure_component("bootloader", bl_image)
        attestation_service.measure_component("application", app_image)
        report = attestation_service.generate_attestation_report()
        assert "bootloader" in report["measurements"]
        assert "application" in report["measurements"]
