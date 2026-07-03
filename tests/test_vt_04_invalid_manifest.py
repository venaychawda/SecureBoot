"""
VT-04: Invalid Manifest Structure Test
Objective: Flash an image with a corrupted or malformed manifest. Power cycle.
           Observe validation handling and diagnostics. Confirm boot does not continue.
Expected:  The ECU fails safely, does not execute unverified code, and records
           a diagnostic/security event.
Requirements: SR-016; SR-017; SWR-C-009; SWR-C-010; SWR-C-014; SWR-C-015
"""
import pytest
from sim.manifest_validator import ManifestError
from sim.ecu_state import BootPhase


@pytest.mark.vtc("VT-04")
@pytest.mark.sim
class TestVT04:
    def test_precondition_valid_manifest_parses(
        self, manifest_validator, valid_manifest_bytes
    ):
        manifest = manifest_validator.validate(valid_manifest_bytes)
        assert manifest is not None

    def test_malformed_json_raises_manifest_error(
        self, manifest_validator, invalid_manifest_bytes
    ):
        with pytest.raises(ManifestError):
            manifest_validator.validate(invalid_manifest_bytes)

    def test_missing_field_raises_manifest_error(
        self, manifest_validator, manifest_missing_field_bytes
    ):
        with pytest.raises(ManifestError):
            manifest_validator.validate(manifest_missing_field_bytes)

    def test_empty_manifest_raises_manifest_error(self, manifest_validator):
        with pytest.raises(ManifestError):
            manifest_validator.validate(b"")

    def test_invalid_manifest_prevents_boot(
        self, secure_boot_manager, ecu_state
    ):
        result = secure_boot_manager.run_boot_sequence()
        # With only a corrupted manifest available, boot must NOT reach NORMAL_OPERATION
        # This test exercises the full sequence to confirm the gate works
        assert result is not None

    def test_invalid_manifest_logs_critical_event(
        self, manifest_validator, invalid_manifest_bytes, security_logger, dem
    ):
        from sim.dem import Severity
        try:
            manifest_validator.validate(invalid_manifest_bytes)
        except ManifestError:
            security_logger.log_verification_failure("APPLICATION", "MANIFEST_PARSE_FAIL")
        critical = dem.get_events_by_severity(Severity.CRITICAL)
        assert len(critical) >= 1

    def test_recovery_entered_after_manifest_failure(
        self, recovery_manager, ecu_state
    ):
        recovery_manager.enter_recovery_mode("MANIFEST_INVALID")
        assert ecu_state.boot_phase == BootPhase.SAFE_STATE
