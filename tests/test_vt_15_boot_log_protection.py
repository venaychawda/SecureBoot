"""
VT-15: Boot Log Protection Test
Objective: Generate security events during boot. Attempt to modify stored boot/security logs.
           Verify log integrity protection mechanisms. Check whether tampering is detected.
Expected:  Log tampering is detected and logs remain trustworthy for forensic use.
Requirements: SWR-C-010; SWR-C-015
"""
import pytest
from sim.dem import Severity


@pytest.mark.vtc("VT-15")
@pytest.mark.sim
class TestVT15:
    def test_precondition_log_integrity_passes_on_fresh_store(
        self, security_logger
    ):
        result = security_logger.verify_log_integrity()
        assert result is True

    def test_events_are_persisted_to_nvm(
        self, security_logger, nvm
    ):
        security_logger.log_boot_event("BOOT_ROM_INIT")
        log = security_logger.get_audit_log()
        assert len(log) >= 1

    def test_direct_nvm_tamper_detected(self, security_logger, nvm):
        security_logger.log_boot_event("TEST_EVENT")
        nvm.write("audit_log_hash_chain", "0" * 64)  # overwrite with wrong hash hex
        result = security_logger.verify_log_integrity()
        assert result is False

    def test_appended_event_maintains_valid_chain(self, security_logger):
        security_logger.log_boot_event("STAGE_1")
        security_logger.log_boot_event("STAGE_2")
        assert security_logger.verify_log_integrity() is True

    def test_log_returns_last_n_entries(self, security_logger):
        for i in range(10):
            security_logger.log_boot_event(f"BOOT_STEP_{i}")
        last_5 = security_logger.get_audit_log(last_n=5)
        assert len(last_5) == 5

    def test_log_entry_has_required_fields(self, security_logger):
        security_logger.log_verification_failure("BOOTLOADER", "sig_invalid")
        log = security_logger.get_audit_log(last_n=1)
        entry = log[0]
        assert "event_type" in entry
        assert "timestamp" in entry
        assert "severity" in entry
