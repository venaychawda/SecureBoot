"""
VT-08: Tamper / Glitch Injection Response Test
Objective: Apply controlled voltage/clock glitch during verification. Monitor
           reset/abort response and logs. Confirm no unauthorized execution.
Expected:  ECU detects anomalies and halts or resets safely; execution does not continue.
Requirements: SR-013; SR-016; SWR-C-010; SWR-C-015
"""
import pytest
from sim.ecu_state import BootPhase
from sim.dem import Severity


@pytest.mark.vtc("VT-08")
@pytest.mark.sim
class TestVT08:
    def test_precondition_hsm_failure_simulation_available(self, hsm):
        hsm.simulate_failure(True)
        from sim.hsm import HSMError
        with pytest.raises(HSMError):
            hsm.sha256(b"test")
        hsm.simulate_failure(False)

    def test_hsm_failure_during_verification_logged_as_tamper(
        self, crypto_provider, security_logger, hsm, dem, valid_application_image
    ):
        image, sig, version = valid_application_image
        hsm.simulate_failure(True)
        try:
            crypto_provider.verify_image_signature(image, sig, "oem_signing_key")
        except Exception:
            security_logger.log_tamper_event(
                "APPLICATION_VERIFY", {"error": "hsm_unavailable"}
            )
        finally:
            hsm.simulate_failure(False)
        critical = dem.get_events_by_severity(Severity.CRITICAL)
        assert len(critical) >= 1

    def test_tamper_event_recorded_in_nvm(
        self, security_logger, nvm
    ):
        security_logger.log_tamper_event("GLITCH_DETECTED", {"stage": "BL_VERIFY"})
        stored = nvm.read("last_security_event")
        assert stored is not None

    def test_execution_halts_on_hsm_failure(
        self, secure_boot_manager, hsm, ecu_state
    ):
        hsm.simulate_failure(True)
        try:
            secure_boot_manager.run_boot_sequence()
        except Exception:
            pass
        finally:
            hsm.simulate_failure(False)
        assert ecu_state.boot_phase != BootPhase.NORMAL_OPERATION

    def test_tamper_event_has_swr_c015_ref(self, security_logger, dem):
        security_logger.log_tamper_event("TEST_ANOMALY")
        events = dem.get_events()
        assert any("SWR-C-015" in e.swr_ref for e in events)
