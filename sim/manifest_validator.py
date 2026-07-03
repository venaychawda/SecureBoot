"""ManifestValidator — firmware image manifest parsing and validation.

Manifests are UTF-8 JSON blobs containing image_hash, signature, version,
component, key_id, not_after (required), and not_before (optional).

SWR-C-008  Manifest structure enforcement
SWR-C-014  Reject images with invalid manifests or corrupted metadata
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone


class ManifestError(Exception):
    pass


@dataclass
class Manifest:
    """Parsed and validated firmware manifest."""

    image_hash: bytes
    signature: bytes
    version: int
    component: str
    key_id: str


_REQUIRED_FIELDS = frozenset(
    {"image_hash", "signature", "version", "component", "key_id", "not_after"}
)


class ManifestValidator:
    """Parses and validates firmware manifests against structural and temporal rules."""

    def __init__(self) -> None:
        pass

    def validate(self, manifest_data: bytes) -> Manifest:
        """Parse and fully validate a manifest.

        Args:
            manifest_data: Raw UTF-8 JSON manifest bytes.

        Returns:
            Populated Manifest dataclass.

        Raises:
            ManifestError: If malformed, missing fields, or outside validity window.
        """
        parsed = self.parse(manifest_data)
        if not self.check_required_fields(parsed):
            raise ManifestError("missing_or_invalid_fields")
        try:
            image_hash = base64.b64decode(parsed["image_hash"])
            signature = base64.b64decode(parsed["signature"])
        except Exception as exc:
            raise ManifestError("base64_decode_failed") from exc
        return Manifest(
            image_hash=image_hash,
            signature=signature,
            version=int(parsed["version"]),
            component=str(parsed["component"]),
            key_id=str(parsed["key_id"]),
        )

    def parse(self, raw: bytes) -> dict:
        """Decode manifest JSON bytes into a dict.

        Args:
            raw: Raw bytes (must be valid UTF-8 JSON).

        Returns:
            Parsed dict.

        Raises:
            ManifestError: If the bytes are not valid JSON.
        """
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise ManifestError("invalid_json") from exc

    def check_required_fields(self, parsed: dict) -> bool:
        """Check field presence and certificate validity window.

        Enforces:
        - All fields in _REQUIRED_FIELDS must be present.
        - not_after must be in the future (UTC).
        - not_before, if present, must be in the past (UTC).

        Args:
            parsed: Previously parsed manifest dict.

        Returns:
            True if all checks pass; False otherwise.
        """
        for field in _REQUIRED_FIELDS:
            if field not in parsed:
                return False

        now = datetime.now(timezone.utc)

        try:
            not_after = datetime.fromisoformat(
                parsed["not_after"].replace("Z", "+00:00")
            )
            if now > not_after:
                return False
        except (ValueError, AttributeError, KeyError):
            return False

        if "not_before" in parsed:
            try:
                not_before = datetime.fromisoformat(
                    parsed["not_before"].replace("Z", "+00:00")
                )
                if now < not_before:
                    return False
            except (ValueError, AttributeError):
                return False

        return True
