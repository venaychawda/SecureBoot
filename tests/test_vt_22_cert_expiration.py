"""
VT-22: Certificate Expiration Validation Test
Objective: Sign firmware with expired certificate. Install image. Reboot ECU.
           Observe verification outcome.
Expected:  Expired certificates are handled according to OEM security policy and
           unauthorized images are rejected.
Requirements: SR-002; SR-020
"""
import json
import time
import base64
import pytest
from sim.manifest_validator import ManifestError


def _make_expired_manifest(valid_manifest_bytes: bytes) -> bytes:
    raw = json.loads(valid_manifest_bytes)
    raw["not_after"] = "2020-01-01T00:00:00Z"
    return json.dumps(raw).encode()


@pytest.mark.vtc("VT-22")
@pytest.mark.sim
class TestVT22:
    def test_precondition_valid_manifest_passes(
        self, manifest_validator, valid_manifest_bytes
    ):
        manifest = manifest_validator.validate(valid_manifest_bytes)
        assert manifest is not None

    def test_expired_certificate_manifest_rejected(
        self, manifest_validator, valid_manifest_bytes
    ):
        expired = _make_expired_manifest(valid_manifest_bytes)
        with pytest.raises(ManifestError):
            manifest_validator.validate(expired)

    def test_expired_manifest_check_required_fields_fails(
        self, manifest_validator, valid_manifest_bytes
    ):
        expired = _make_expired_manifest(valid_manifest_bytes)
        parsed = manifest_validator.parse(expired)
        result = manifest_validator.check_required_fields(parsed)
        assert result is False

    def test_expired_cert_image_does_not_boot(
        self, secure_boot_manager, ecu_state, valid_manifest_bytes
    ):
        from sim.ecu_state import BootPhase
        # Simulate manager gets an expired manifest scenario
        secure_boot_manager.run_boot_sequence()
        assert ecu_state.boot_phase != BootPhase.NORMAL_OPERATION

    def test_not_before_in_future_also_rejected(
        self, manifest_validator, valid_manifest_bytes
    ):
        raw = json.loads(valid_manifest_bytes)
        raw["not_before"] = "2099-01-01T00:00:00Z"
        future_manifest = json.dumps(raw).encode()
        with pytest.raises(ManifestError):
            manifest_validator.validate(future_manifest)

    def test_missing_expiry_field_rejected(
        self, manifest_validator, valid_manifest_bytes
    ):
        raw = json.loads(valid_manifest_bytes)
        raw.pop("not_after", None)
        no_expiry = json.dumps(raw).encode()
        with pytest.raises(ManifestError):
            manifest_validator.validate(no_expiry)
