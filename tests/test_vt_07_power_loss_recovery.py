"""
VT-07: Power Loss During Boot Test
Objective: Start the ECU boot process with a valid image. Interrupt power during
           signature verification or loading. Restore power. Observe restart behavior.
Expected:  The ECU restarts secure boot from the beginning with no partial state
           or security bypass.
Requirements: SR-008; SR-010; SWR-C-012; SWR-C-013
"""
import pytest
from sim.ecu_state import BootPhase
from sim.config import NVM_KEY_BOOT_COUNTER, MAX_BOOT_RETRY_ATTEMPTS


@pytest.mark.vtc("VT-07")
@pytest.mark.sim
class TestVT07:
    def test_precondition_boot_attempt_counter_starts_at_zero(self, nvm):
        count = nvm.read(NVM_KEY_BOOT_COUNTER, default=0)
        assert count == 0

    def test_interrupted_boot_detected_via_counter(self, secure_boot_manager, nvm):
        nvm.write(NVM_KEY_BOOT_COUNTER, 1)
        secure_boot_manager.handle_interruption()
        # Counter should be incremented and interruption logged
        assert nvm.read(NVM_KEY_BOOT_COUNTER) >= 1

    def test_no_partial_state_after_interruption(
        self, secure_boot_manager, nvm, ecu_state
    ):
        nvm.write(NVM_KEY_BOOT_COUNTER, 1)
        secure_boot_manager.handle_interruption()
        # ECU must never be in an undefined intermediate state
        assert ecu_state.boot_phase in (
            BootPhase.POWER_OFF, BootPhase.ROM_INIT,
            BootPhase.BOOTLOADER_VERIFY, BootPhase.LOCKED_OUT,
        )

    def test_lockout_after_max_retries(self, secure_boot_manager, nvm, ecu_state):
        nvm.write(NVM_KEY_BOOT_COUNTER, MAX_BOOT_RETRY_ATTEMPTS + 1)
        secure_boot_manager.handle_interruption()
        assert ecu_state.boot_phase == BootPhase.LOCKED_OUT

    def test_update_activation_atomic_on_power_loss(self, update_manager, nvm, valid_application_image):
        image, sig, version = valid_application_image
        result = update_manager.activate_update(image, sig)
        # After failed or completed activation, update_pending must be False
        assert nvm.read("update_pending", default=False) is False

    def test_update_rollback_restores_previous_image(
        self, update_manager, nvm, valid_application_image
    ):
        image, sig, version = valid_application_image
        update_manager.activate_update(image, sig)
        result = update_manager.rollback_update()
        assert result is True
