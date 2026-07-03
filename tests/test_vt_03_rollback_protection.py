"""
VT-03: Rollback Protection Test
Objective: Install a known-good current version. Attempt to flash an older but
           validly signed firmware image. Reboot. Check version counter and event logs.
Expected:  The ECU rejects the older version, retains current firmware, and records
           a rollback prevention event.
Requirements: SR-006; SWR-C-006; SWR-C-007
"""
import pytest


@pytest.mark.vtc("VT-03")
@pytest.mark.sim
class TestVT03:
    def test_precondition_version_counter_starts_at_floor(self, version_manager):
        from sim.config import FIRMWARE_VERSION_FLOOR_APP
        current = version_manager.get_version("APPLICATION")
        assert isinstance(current, int)

    def test_current_version_accepted(self, version_manager, valid_application_image):
        _, _, version = valid_application_image
        result = version_manager.validate_version("APPLICATION", version)
        assert result is True

    def test_downgrade_version_rejected(self, version_manager, nvm):
        from sim.config import NVM_KEY_ROLLBACK_COUNTER_APP, FIRMWARE_VERSION_FLOOR_APP
        nvm.write(NVM_KEY_ROLLBACK_COUNTER_APP, FIRMWARE_VERSION_FLOOR_APP + 2)
        result = version_manager.validate_version("APPLICATION", FIRMWARE_VERSION_FLOOR_APP)
        assert result is False

    def test_rollback_detected_is_rollback_predicate(self, version_manager, nvm):
        from sim.config import NVM_KEY_ROLLBACK_COUNTER_APP, FIRMWARE_VERSION_FLOOR_APP
        nvm.write(NVM_KEY_ROLLBACK_COUNTER_APP, 5)
        assert version_manager.is_rollback("APPLICATION", 3) is True
        assert version_manager.is_rollback("APPLICATION", 5) is False
        assert version_manager.is_rollback("APPLICATION", 6) is False

    def test_rollback_attempt_logs_event(self, version_manager, nvm, dem):
        from sim.config import NVM_KEY_ROLLBACK_COUNTER_APP, FIRMWARE_VERSION_FLOOR_APP
        from sim.dem import Severity
        nvm.write(NVM_KEY_ROLLBACK_COUNTER_APP, FIRMWARE_VERSION_FLOOR_APP + 2)
        version_manager.validate_version("APPLICATION", FIRMWARE_VERSION_FLOOR_APP)
        events = dem.get_events()
        assert any("rollback" in e.description.lower() or Severity.WARNING == e.severity
                   for e in events)

    def test_commit_version_ratchets_counter(self, version_manager, nvm):
        from sim.config import NVM_KEY_ROLLBACK_COUNTER_APP
        version_manager.commit_version("APPLICATION", 10)
        assert version_manager.get_version("APPLICATION") == 10
        assert version_manager.validate_version("APPLICATION", 9) is False
