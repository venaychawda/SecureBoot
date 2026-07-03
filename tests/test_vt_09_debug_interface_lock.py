"""
VT-09: Debug Interface Lock Test
Objective: Place ECU in production lifecycle state. Attempt JTAG/SWD connection
           during and after boot. Attempt memory readout or halt/debug attach.
Expected:  Unauthorized debug access fails; firmware extraction or modification prevented.
Requirements: SR-014; SWR-C-011
"""
import pytest
from sim.debug_manager import DebugManagerError


@pytest.mark.vtc("VT-09")
@pytest.mark.sim
class TestVT09:
    def test_precondition_debug_locked_in_production(self, debug_manager_production):
        debug_manager_production.check_debug_lock_on_startup()
        assert debug_manager_production.is_debug_locked() is True

    def test_unauthorized_debug_access_denied(self, debug_manager_production):
        bad_credential = b"\x00" * 64
        result = debug_manager_production.gate_debug_access(bad_credential)
        assert result is False

    def test_invalid_credential_logs_critical_event(
        self, debug_manager_production, dem
    ):
        bad_credential = b"\x00" * 64
        debug_manager_production.gate_debug_access(bad_credential)
        from sim.dem import Severity
        critical = dem.get_events_by_severity(Severity.CRITICAL)
        assert len(critical) >= 1

    def test_valid_credential_grants_access_in_production(
        self, debug_manager_production, hsm
    ):
        from sim.config import HSM_KEY_ID_DEBUG_AUTH
        challenge = b"debug_access_request_v1"
        credential = hsm.sign(HSM_KEY_ID_DEBUG_AUTH, challenge)
        result = debug_manager_production.gate_debug_access(credential)
        assert result is True

    def test_debug_open_in_development_lifecycle(self, debug_manager):
        debug_manager.check_debug_lock_on_startup()
        assert debug_manager.is_debug_locked() is False

    def test_debug_lock_status_included_in_status_dict(self, debug_manager_production):
        debug_manager_production.check_debug_lock_on_startup()
        status = debug_manager_production.get_status()
        assert "debug_locked" in status
        assert status["debug_locked"] is True
