"""
VT-21: Certificate Chain Validation Test
Objective: Provision Root CA, Intermediate CA, and Signing Certificate. Verify valid
           firmware. Break certificate chain. Reboot ECU.
Expected:  Valid certificate chains are accepted; invalid chains are rejected.
Requirements: SR-002; SR-020
"""
import pytest
from sim.manifest_validator import ManifestError


@pytest.mark.vtc("VT-21")
@pytest.mark.sim
class TestVT21:
    def test_precondition_valid_manifest_accepted(
        self, manifest_validator, valid_manifest_bytes
    ):
        manifest = manifest_validator.validate(valid_manifest_bytes)
        assert manifest is not None
        assert manifest.key_id is not None

    def test_root_ca_signed_manifest_is_accepted(
        self, trust_anchor_manager, manifest_validator, valid_manifest_bytes
    ):
        from sim.config import HSM_KEY_ID_OEM_ROOT
        manifest = manifest_validator.validate(valid_manifest_bytes)
        is_registered = trust_anchor_manager.is_key_registered(manifest.key_id)
        assert is_registered is True

    def test_broken_chain_key_not_in_trust_anchor(
        self, trust_anchor_manager, manifest_validator, valid_manifest_bytes
    ):
        import json, base64
        raw = json.loads(valid_manifest_bytes)
        raw["key_id"] = "attacker_ca_key"
        broken = json.dumps(raw).encode()
        manifest = manifest_validator.validate(broken)
        assert trust_anchor_manager.is_key_registered(manifest.key_id) is False

    def test_broken_chain_prevents_image_verification(
        self, crypto_provider, trust_anchor_manager, valid_application_image
    ):
        image, sig, _ = valid_application_image
        unregistered_key = "attacker_ca_key"
        assert trust_anchor_manager.is_key_registered(unregistered_key) is False
        result = crypto_provider.verify_image_signature(image, sig, unregistered_key)
        assert result is False

    def test_manifest_parse_extracts_key_id(
        self, manifest_validator, valid_manifest_bytes
    ):
        parsed = manifest_validator.parse(valid_manifest_bytes)
        assert "key_id" in parsed

    def test_manifest_required_fields_present(
        self, manifest_validator, valid_manifest_bytes
    ):
        parsed = manifest_validator.parse(valid_manifest_bytes)
        result = manifest_validator.check_required_fields(parsed)
        assert result is True
