"""
VT-12: Replay Attack Simulation Test
Objective: Flash and accept a valid firmware image. Attempt to reflash the same image
           or reuse stale update metadata. Reboot the ECU. Observe version/freshness checks.
Expected:  Replay is detected and blocked by version counters or freshness controls.
Requirements: SR-012; SWR-C-006; SWR-C-007
"""
import pytest
from sim.version_manager import VersionError
from sim.config import NVM_KEY_ROLLBACK_COUNTER_APP, FIRMWARE_VERSION_FLOOR_APP


@pytest.mark.vtc("VT-12")
@pytest.mark.sim
class TestVT12:
    def test_precondition_version_floor_is_enforced(self, version_manager):
        # Version equal to floor is valid; below floor is a replay/rollback
        result = version_manager.validate_version("application", FIRMWARE_VERSION_FLOOR_APP)
        assert result is True

    def test_same_version_reflash_is_blocked(self, version_manager):
        version_manager.commit_version("application", 2)
        # Attempting the same version again is a replay
        result = version_manager.validate_version("application", 2)
        assert result is False

    def test_older_version_reflash_is_blocked(self, version_manager):
        version_manager.commit_version("application", 3)
        result = version_manager.validate_version("application", 2)
        assert result is False

    def test_newer_version_is_accepted(self, version_manager):
        version_manager.commit_version("application", 2)
        result = version_manager.validate_version("application", 3)
        assert result is True

    def test_rollback_counter_increments_on_commit(self, version_manager, nvm):
        before = nvm.read(NVM_KEY_ROLLBACK_COUNTER_APP, default=0)
        version_manager.commit_version("application", before + 1)
        after = nvm.read(NVM_KEY_ROLLBACK_COUNTER_APP)
        assert after > before

    def test_update_manager_rejects_stale_package(
        self, update_manager, valid_application_image, version_manager
    ):
        image, sig, version = valid_application_image
        version_manager.commit_version("application", version)
        result = update_manager.validate_update_package(image, sig)
        assert result is False
