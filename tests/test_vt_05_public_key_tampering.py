"""
VT-05: Public Key Tampering Test
Objective: Attempt to modify or replace the OEM verification key or fuse value.
           Reset/power cycle the ECU. Observe root-of-trust validation.
Expected:  Tampering is detected, verification fails, ECU halts or enters secure
           lockdown without trusting modified keys.
Requirements: SR-001; SR-002; SWR-C-001
"""
import pytest
from sim.hsm import HSMError
from sim.trust_anchor_manager import TrustAnchorError


@pytest.mark.vtc("VT-05")
@pytest.mark.sim
class TestVT05:
    def test_precondition_oem_key_registered(self, trust_anchor_manager):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        assert trust_anchor_manager.is_key_registered(HSM_KEY_ID_OEM_SIGNING) is True

    def test_get_public_key_returns_pem(self, trust_anchor_manager):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        pem = trust_anchor_manager.get_oem_public_key(HSM_KEY_ID_OEM_SIGNING)
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_unknown_key_raises_error(self, trust_anchor_manager):
        with pytest.raises(TrustAnchorError):
            trust_anchor_manager.get_oem_public_key("non_existent_key_id")

    def test_verification_fails_with_wrong_key(self, crypto_provider, valid_bootloader_image, hsm):
        image, _, version = valid_bootloader_image
        hsm.generate_key_pair("attacker_key")
        attacker_sig = hsm.sign("attacker_key", image)
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        result = crypto_provider.verify_image_signature(image, attacker_sig, HSM_KEY_ID_OEM_SIGNING)
        assert result is False

    def test_unauthorized_key_rotation_rejected(self, trust_anchor_manager, hsm):
        bad_authorization = b"\x00" * 64
        result = trust_anchor_manager.rotate_key("new_key_id", bad_authorization)
        assert result is False

    def test_authorized_key_rotation_accepted(self, trust_anchor_manager, hsm):
        from sim.config import HSM_KEY_ID_OEM_ROOT
        new_key_id = "oem_signing_key_v2"
        authorization_sig = hsm.sign(HSM_KEY_ID_OEM_ROOT, new_key_id.encode())
        result = trust_anchor_manager.rotate_key(new_key_id, authorization_sig)
        assert result is True
        assert trust_anchor_manager.is_key_registered(new_key_id) is True
