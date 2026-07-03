"""TrustAnchorManager — OEM root-of-trust key registry.

Exposes only public-key material to callers; private key bytes never leave hsm.py.
Key rotation requires a valid authorization signature from the OEM root key.

SR-002   Protect trust anchor; support authorized key rotation
SR-011   Private keys confined to HSM
SR-020   Algorithm migration and key rotation without hardware replacement
SWR-C-005  ECDSA verification using provisioned OEM public keys
"""
from __future__ import annotations

from sim.config import (
    HSM_KEY_ID_BOOTLOADER,
    HSM_KEY_ID_DEBUG_AUTH,
    HSM_KEY_ID_OEM_ROOT,
    HSM_KEY_ID_OEM_SIGNING,
)
from sim.hsm import HSM, HSMError


class TrustAnchorError(Exception):
    pass


_DEFAULT_KEY_IDS = (
    HSM_KEY_ID_OEM_ROOT,
    HSM_KEY_ID_OEM_SIGNING,
    HSM_KEY_ID_BOOTLOADER,
    HSM_KEY_ID_DEBUG_AUTH,
)


class TrustAnchorManager:
    """Manages the set of registered OEM keys and enforces key-boundary policy."""

    def __init__(self, hsm: HSM, sl: object) -> None:
        self._hsm = hsm
        self._sl = sl
        self._registered: set[str] = set()
        for kid in _DEFAULT_KEY_IDS:
            try:
                self._hsm.get_public_key_pem(kid)
                self._registered.add(kid)
            except HSMError:
                pass

    def get_oem_public_key(self, key_id: str) -> bytes:
        """Return PEM-encoded public key — never private key material.

        Args:
            key_id: Registered key identifier.

        Returns:
            PEM bytes of the public key.

        Raises:
            TrustAnchorError: If key_id is not registered.
        """
        if key_id not in self._registered:
            raise TrustAnchorError(f"unregistered_key: {key_id}")
        try:
            return self._hsm.get_public_key_pem(key_id)
        except HSMError as exc:
            raise TrustAnchorError("hsm_unavailable") from exc

    def rotate_key(self, new_key_id: str, authorization_sig: bytes) -> bool:
        """Register a new signing key if the rotation is authorized by the root key.

        Args:
            new_key_id: Identifier for the new key pair to generate.
            authorization_sig: ECDSA signature of new_key_id.encode() under OEM root key.

        Returns:
            True if rotation succeeded; False if unauthorized.
        """
        try:
            valid = self._hsm.verify(
                HSM_KEY_ID_OEM_ROOT, new_key_id.encode(), authorization_sig
            )
        except Exception:
            valid = False

        if valid:
            self._hsm.generate_key_pair(new_key_id)
            self._registered.add(new_key_id)
            self._sl.log_boot_event("KEY_ROTATED", {"key_id": new_key_id})
        else:
            self._sl.log_tamper_event("KEY_ROTATION_REJECTED", {"key_id": new_key_id})
        return valid

    def is_key_registered(self, key_id: str) -> bool:
        """Return True if key_id is in the registered trust anchor set.

        Args:
            key_id: Key identifier to check.
        """
        return key_id in self._registered

    def get_registered_key_ids(self) -> list[str]:
        """Return a list of all registered key identifiers."""
        return list(self._registered)
