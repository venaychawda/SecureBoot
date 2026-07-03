"""
VT-13: Hash Integrity Check Test
Objective: Flash a valid image. Modify one or more bits in the image payload.
           Reboot the ECU. Observe hash verification outcome.
Expected:  Hash mismatch is detected and boot stops before executing altered image data.
Requirements: SWR-C-003; SWR-C-014
"""
import pytest
from sim.ecu_state import BootPhase
from sim.dem import Severity


@pytest.mark.vtc("VT-13")
@pytest.mark.sim
class TestVT13:
    def test_precondition_clean_image_passes_hash_check(
        self, crypto_provider, valid_application_image, trust_anchor_manager
    ):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        image, sig, _ = valid_application_image
        result = crypto_provider.verify_image_signature(image, sig, HSM_KEY_ID_OEM_SIGNING)
        assert result is True

    def test_single_bit_flip_detected(
        self, crypto_provider, valid_application_image
    ):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        image, sig, _ = valid_application_image
        tampered = bytearray(image)
        tampered[0] ^= 0x01
        result = crypto_provider.verify_image_signature(
            bytes(tampered), sig, HSM_KEY_ID_OEM_SIGNING
        )
        assert result is False

    def test_last_byte_modification_detected(
        self, crypto_provider, valid_application_image
    ):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        image, sig, _ = valid_application_image
        tampered = bytearray(image)
        tampered[-1] ^= 0xFF
        result = crypto_provider.verify_image_signature(
            bytes(tampered), sig, HSM_KEY_ID_OEM_SIGNING
        )
        assert result is False

    def test_hash_mismatch_prevents_boot(
        self, secure_boot_manager, tampered_application_image, ecu_state
    ):
        secure_boot_manager.run_boot_sequence()
        assert ecu_state.boot_phase != BootPhase.NORMAL_OPERATION

    def test_hash_failure_logged_as_critical(
        self, crypto_provider, security_logger, valid_application_image, dem
    ):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        image, sig, _ = valid_application_image
        tampered = bytes([b ^ 0x01 for b in image])
        ok = crypto_provider.verify_image_signature(tampered, sig, HSM_KEY_ID_OEM_SIGNING)
        if not ok:
            security_logger.log_verification_failure(
                "APPLICATION_VERIFY", "hash_mismatch"
            )
        critical = dem.get_events_by_severity(Severity.CRITICAL)
        assert len(critical) >= 1

    def test_image_hash_computation_is_deterministic(
        self, crypto_provider, valid_application_image
    ):
        image, _, _ = valid_application_image
        h1 = crypto_provider.compute_image_hash(image)
        h2 = crypto_provider.compute_image_hash(image)
        assert h1 == h2
