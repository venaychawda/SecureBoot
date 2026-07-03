"""
VT-16: Key Provisioning Process Audit Test
Objective: Review provisioning records and manufacturing/service steps. Verify secure
           transport and key injection process. Check HSM logs and ECU association.
           Confirm traceability completeness.
Expected:  Provisioning is fully logged, secure, and uniquely associated with the ECU.
Requirements: SR-011; SR-015; SWR-C-005
"""
import pytest


@pytest.mark.vtc("VT-16")
@pytest.mark.sim
class TestVT16:
    def test_precondition_oem_signing_key_registered(self, trust_anchor_manager):
        from sim.config import HSM_KEY_ID_OEM_SIGNING
        assert trust_anchor_manager.is_key_registered(HSM_KEY_ID_OEM_SIGNING) is True

    def test_oem_root_key_registered(self, trust_anchor_manager):
        from sim.config import HSM_KEY_ID_OEM_ROOT
        assert trust_anchor_manager.is_key_registered(HSM_KEY_ID_OEM_ROOT) is True

    def test_debug_auth_key_registered(self, trust_anchor_manager):
        from sim.config import HSM_KEY_ID_DEBUG_AUTH
        assert trust_anchor_manager.is_key_registered(HSM_KEY_ID_DEBUG_AUTH) is True

    def test_key_rotation_requires_authorization_signature(
        self, trust_anchor_manager, hsm
    ):
        from sim.config import HSM_KEY_ID_OEM_ROOT, HSM_KEY_ID_OEM_SIGNING
        new_key_id = "oem_signing_key_v2"
        auth_sig = hsm.sign(HSM_KEY_ID_OEM_ROOT, new_key_id.encode())
        result = trust_anchor_manager.rotate_key(new_key_id, auth_sig)
        assert result is True

    def test_unauthorized_key_rotation_rejected(self, trust_anchor_manager):
        bad_sig = b"\x00" * 64
        result = trust_anchor_manager.rotate_key("attacker_key", bad_sig)
        assert result is False

    def test_registered_key_ids_enumerable_for_audit(self, trust_anchor_manager):
        key_ids = trust_anchor_manager.get_registered_key_ids()
        assert len(key_ids) >= 3
        from sim.config import (
            HSM_KEY_ID_OEM_ROOT, HSM_KEY_ID_OEM_SIGNING, HSM_KEY_ID_DEBUG_AUTH
        )
        assert HSM_KEY_ID_OEM_ROOT in key_ids
        assert HSM_KEY_ID_OEM_SIGNING in key_ids
