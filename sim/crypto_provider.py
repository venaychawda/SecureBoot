"""CryptoProvider — policy-compliant SHA-256 / ECDSA-P256 service layer.

Routes through CSM → CryIf → HSM.  No direct HSM access outside hsm.py.

SWR-C-003  Image integrity via SHA-256
SWR-C-004  Approved algorithms only
SWR-C-005  ECDSA P-256 signature verification
"""
from __future__ import annotations

from sim.config import APPROVED_HASH_ALGORITHM, APPROVED_SIGNATURE_ALGORITHM
from sim.csm import CSM


class CryptoProviderError(Exception):
    pass


class CryptoProvider:
    """Provides image-level hash and signature operations via the CSM stack."""

    def __init__(self, csm: CSM) -> None:
        self._csm = csm

    def compute_image_hash(self, image_data: bytes) -> bytes:
        """Compute SHA-256 of a firmware image via CSM.

        Args:
            image_data: Raw firmware bytes.

        Returns:
            32-byte SHA-256 digest.

        Raises:
            CryptoProviderError: On underlying crypto failure.
        """
        try:
            return self._csm.compute_hash(image_data)
        except Exception as exc:
            raise CryptoProviderError("hash_failed") from exc

    def verify_image_signature(
        self, image_data: bytes, signature: bytes, key_id: str
    ) -> bool:
        """Verify ECDSA P-256 signature of a firmware image via CSM.

        Returns False for invalid signatures. Re-raises CryptoProviderError for
        hardware-level failures (HSM unavailable) so callers can distinguish
        infrastructure faults from cryptographic rejections.

        Args:
            image_data: Raw firmware bytes that were signed.
            signature: DER-encoded ECDSA signature.
            key_id: HSM key pair identifier.

        Returns:
            True if the signature is valid; False if cryptographically invalid.

        Raises:
            CryptoProviderError: If the underlying HSM/CSM is unavailable.
        """
        from sim.csm import CSMError
        from sim.hsm import HSMError
        try:
            return self._csm.verify_signature(image_data, signature, key_id)
        except CSMError as exc:
            cause = exc.__cause__
            if isinstance(cause, HSMError) and "unavailable" in str(cause):
                raise CryptoProviderError("hsm_unavailable") from exc
            return False
        except Exception:
            return False

    def get_algorithm_info(self) -> dict:
        """Return the approved algorithm identifiers for compliance inspection.

        Returns:
            Dict with hash_algorithm and signature_algorithm keys.
        """
        return {
            "hash_algorithm": APPROVED_HASH_ALGORITHM,
            "signature_algorithm": APPROVED_SIGNATURE_ALGORITHM,
        }
