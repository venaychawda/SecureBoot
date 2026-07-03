"""AttestationService — measured boot component hash recording.

Each boot stage is hashed via CSM and recorded in-memory and in NvM.
Attestation reports aggregate all measurements for remote verification.

SR-019  Measured boot — record component hashes for backend attestation
"""
from __future__ import annotations

import time

from sim.config import NVM_KEY_ATTESTATION_LOG
from sim.csm import CSM


class AttestationError(Exception):
    pass


class AttestationService:
    """Records per-component boot measurements and produces attestation reports."""

    def __init__(self, csm: CSM, nvm: object, sl: object) -> None:
        self._csm = csm
        self._nvm = nvm
        self._sl = sl
        self._measurements: dict[str, bytes] = {}

    def measure_component(self, component_id: str, image_data: bytes) -> bytes:
        """Hash image_data, record in memory and NvM, return digest.

        Args:
            component_id: Logical component name (e.g. "bootloader", "application").
            image_data: Raw firmware bytes to measure.

        Returns:
            32-byte SHA-256 digest of image_data.
        """
        try:
            digest = self._csm.compute_hash(image_data)
        except Exception as exc:
            raise AttestationError("hash_failed") from exc
        self._measurements[component_id] = digest
        self.record_measurement(component_id, digest)
        self._sl.log_boot_event(
            f"MEASURED_{component_id.upper()}", {"hash": digest.hex()}
        )
        return digest

    def record_measurement(self, component_id: str, hash_bytes: bytes) -> None:
        """Persist a component measurement to the NvM attestation log.

        Args:
            component_id: Component name.
            hash_bytes: 32-byte digest to persist.
        """
        self._measurements[component_id] = hash_bytes
        stored: dict = self._nvm.read(NVM_KEY_ATTESTATION_LOG, default={})
        stored[component_id] = hash_bytes.hex()
        self._nvm.write(NVM_KEY_ATTESTATION_LOG, stored)

    def generate_attestation_report(self) -> dict:
        """Return all in-memory measurements as a timestamped report.

        Returns:
            Dict with "measurements" (component → hex digest) and "timestamp".
        """
        return {
            "measurements": {k: v.hex() for k, v in self._measurements.items()},
            "timestamp": time.time(),
        }

    def get_measurements(self) -> dict[str, bytes]:
        """Return the in-memory measurement cache.

        Returns:
            Dict mapping component_id to raw digest bytes.
        """
        return dict(self._measurements)
