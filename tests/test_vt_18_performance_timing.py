"""
VT-18: Performance and Timing Test
Objective: Measure secure boot duration using instrumentation. Repeat across multiple
           power cycles. Compare against boot-time limits. Record worst-case boot time.
Expected:  Secure boot completes within the defined timing requirement without weakening
           security.
Requirements: SR-006 (boot-time budget)
"""
import time
import pytest
from sim.config import BOOT_STAGE_ROM, BOOT_STAGE_BOOTLOADER, BOOT_STAGE_APPLICATION


BOOT_TIME_BUDGET_SECONDS = 5.0


@pytest.mark.vtc("VT-18")
@pytest.mark.sim
@pytest.mark.slow
class TestVT18:
    def test_full_boot_sequence_completes_within_budget(self, boot_rom):
        start = time.monotonic()
        boot_rom.power_on()
        elapsed = time.monotonic() - start
        assert elapsed < BOOT_TIME_BUDGET_SECONDS, (
            f"Boot sequence took {elapsed:.3f}s; budget is {BOOT_TIME_BUDGET_SECONDS}s"
        )

    def test_crypto_hash_operation_within_10ms(self, crypto_provider, valid_application_image):
        image, _, _ = valid_application_image
        start = time.monotonic()
        crypto_provider.compute_image_hash(image)
        elapsed = time.monotonic() - start
        assert elapsed < 0.010, (
            f"SHA-256 hash took {elapsed * 1000:.2f}ms; expected < 10ms"
        )

    def test_signature_verify_within_50ms(
        self, crypto_provider, valid_application_image
    ):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        image, sig, _ = valid_application_image
        start = time.monotonic()
        crypto_provider.verify_image_signature(image, sig, HSM_KEY_ID_OEM_SIGNING)
        elapsed = time.monotonic() - start
        assert elapsed < 0.050, (
            f"ECDSA verify took {elapsed * 1000:.2f}ms; expected < 50ms"
        )

    def test_boot_timing_consistent_across_runs(self, boot_rom):
        times = []
        for _ in range(3):
            start = time.monotonic()
            boot_rom.power_on()
            times.append(time.monotonic() - start)
        variance = max(times) - min(times)
        assert variance < 1.0, (
            f"Boot time variance {variance:.3f}s exceeds 1s — timing not repeatable"
        )
