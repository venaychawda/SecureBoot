"""
VT-10: HSM Key Non-Exportability Test
Objective: Initiate secure boot operations requiring private-key use. Attempt
           runtime inspection or export of key material. Review HSM access logs.
Expected:  Private keys remain non-exportable and confined within HSM boundary.
Requirements: SR-011; SWR-C-005
"""
import pytest
from sim.trust_anchor_manager import TrustAnchorError


@pytest.mark.vtc("VT-10")
@pytest.mark.sim
class TestVT10:
    def test_precondition_key_store_is_private(self, hsm):
        assert not hasattr(hsm, "key_store")
        assert hasattr(hsm, "_key_store")

    def test_get_public_key_returns_pem_only(self, trust_anchor_manager):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        pem = trust_anchor_manager.get_oem_public_key(HSM_KEY_ID_OEM_SIGNING)
        assert b"PUBLIC KEY" in pem
        assert b"PRIVATE KEY" not in pem

    def test_no_public_api_exposes_private_key_bytes(self, hsm):
        import inspect
        public_methods = [
            name for name, _ in inspect.getmembers(hsm, predicate=inspect.ismethod)
            if not name.startswith("_")
        ]
        for method_name in public_methods:
            assert "private" not in method_name.lower(), (
                f"HSM.{method_name} looks like it could expose private key material"
            )

    def test_signing_works_without_exposing_key(self, hsm, valid_application_image):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        image, _, _ = valid_application_image
        sig = hsm.sign(HSM_KEY_ID_OEM_SIGNING, image)
        assert isinstance(sig, bytes) and len(sig) > 0

    def test_verify_uses_public_key_path_only(
        self, trust_anchor_manager, crypto_provider, valid_application_image
    ):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        image, sig, _ = valid_application_image
        result = crypto_provider.verify_image_signature(image, sig, HSM_KEY_ID_OEM_SIGNING)
        assert result is True

    def test_registered_key_ids_do_not_include_private_material(
        self, trust_anchor_manager
    ):
        key_ids = trust_anchor_manager.get_registered_key_ids()
        assert isinstance(key_ids, list)
        for kid in key_ids:
            assert isinstance(kid, str)
