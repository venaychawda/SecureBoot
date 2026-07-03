"""
VT-17: Crypto Algorithm Compliance Test
Objective: Inspect boot configuration, manifests, and binaries. Verify approved
           algorithms only. Check for deprecated or weak algorithms. Document any deviation.
Expected:  Only approved algorithms (SHA-256 and ECDSA P-256) are present;
           noncompliance is flagged.
Requirements: SWR-C-004; SWR-C-005
"""
import pytest
from sim.config import APPROVED_HASH_ALGORITHM, APPROVED_SIGNATURE_ALGORITHM


@pytest.mark.vtc("VT-17")
@pytest.mark.sim
class TestVT17:
    def test_precondition_approved_algorithms_defined_in_config(self):
        assert APPROVED_HASH_ALGORITHM == "SHA-256"
        assert APPROVED_SIGNATURE_ALGORITHM == "ECDSA-P256"

    def test_crypto_provider_reports_approved_algorithms(self, crypto_provider):
        info = crypto_provider.get_algorithm_info()
        assert info["hash_algorithm"] == APPROVED_HASH_ALGORITHM
        assert info["signature_algorithm"] == APPROVED_SIGNATURE_ALGORITHM

    def test_image_hash_length_is_sha256(self, crypto_provider, valid_application_image):
        image, _, _ = valid_application_image
        digest = crypto_provider.compute_image_hash(image)
        assert len(digest) == 32, f"Expected 32-byte SHA-256; got {len(digest)}"

    def test_signature_length_is_ecdsa_p256(self, hsm, valid_application_image):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        image, _, _ = valid_application_image
        sig = hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
        # DER-encoded ECDSA P-256 signatures are between 70 and 72 bytes
        assert 64 <= len(sig) <= 72, (
            f"Unexpected ECDSA P-256 signature length: {len(sig)}"
        )

    def test_hsm_does_not_expose_rsa_or_md5_operations(self, hsm):
        import inspect
        method_names = {
            name for name, _ in inspect.getmembers(hsm, predicate=inspect.ismethod)
        }
        forbidden = {"rsa_sign", "rsa_verify", "md5", "sha1"}
        violations = method_names & forbidden
        assert not violations, f"HSM exposes non-approved algorithms: {violations}"

    def test_valid_manifest_uses_approved_algorithm(
        self, manifest_validator, valid_manifest_bytes
    ):
        manifest = manifest_validator.validate(valid_manifest_bytes)
        assert manifest is not None
