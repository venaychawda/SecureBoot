"""SecurityLogger — tamper-evident security and boot event recording.

Wraps DEM (AUTOSAR diagnostic events) and HashChainedLog (forensic audit trail).
All security events in the project flow through this module — no print() allowed.
Chain tip is persisted to NvM after every write so NvM tampering is detectable.

SWR-C-010  Audit logging
SWR-C-015  Tamper detection and recording
"""
from __future__ import annotations

from typing import Any

from sim.dem import DEM, HashChainedLog, Severity

_NVM_KEY_CHAIN_TIP = "audit_log_hash_chain"
_NVM_KEY_LAST_EVENT = "last_security_event"


class SecurityLoggerError(Exception):
    pass


class SecurityLogger:
    """Unified security audit interface backed by DEM + hash-chained journal."""

    def __init__(self, dem: DEM, nvm: Any) -> None:
        self._dem = dem
        self._nvm = nvm
        self._chain = HashChainedLog()

    def log_boot_event(self, event_type: str, detail: dict | None = None) -> Any:
        """Record an informational boot-lifecycle event.

        Args:
            event_type: Short event identifier string.
            detail: Optional supplementary data dict.

        Returns:
            The DemEvent created.
        """
        d = detail or {}
        self._chain.log(event_type, d)
        self._persist_chain_tip()
        return self._dem.log(
            event_type, Severity.INFO, f"boot:{event_type}", "SWR-C-010", d
        )

    def log_verification_failure(
        self, stage: str, reason: str, detail: dict | None = None
    ) -> Any:
        """Record a CRITICAL verification failure to DEM and chain.

        Args:
            stage: Boot stage identifier (e.g. "BOOTLOADER", "APPLICATION_VERIFY").
            reason: Machine-readable failure reason.
            detail: Optional extra context dict.

        Returns:
            The DemEvent created.
        """
        d = {"stage": stage, "reason": reason, **(detail or {})}
        event_id = f"VERIFY_FAIL_{stage}"
        self._chain.log(event_id, d)
        self._persist_chain_tip()
        self._nvm.write(
            _NVM_KEY_LAST_EVENT,
            {"event": "VERIFY_FAIL", "stage": stage, "reason": reason},
        )
        return self._dem.log(
            event_id, Severity.CRITICAL, f"verification failure: {reason}", "SWR-C-010", d
        )

    def log_tamper_event(self, context: str, detail: dict | None = None) -> Any:
        """Record a CRITICAL tamper / security anomaly event (SWR-C-015).

        Args:
            context: Short identifier for the tamper context.
            detail: Optional extra context dict.

        Returns:
            The DemEvent created.
        """
        d = {"context": context, **(detail or {})}
        event_id = f"TAMPER_{context}"
        self._chain.log(event_id, d)
        self._persist_chain_tip()
        self._nvm.write(_NVM_KEY_LAST_EVENT, {"event": "TAMPER", "context": context})
        return self._dem.log(
            event_id, Severity.CRITICAL, f"tamper detected: {context}", "SWR-C-015", d
        )

    def get_audit_log(self, last_n: int = 50) -> list[dict]:
        """Return the last N audit log entries from the hash-chained journal.

        Args:
            last_n: Maximum number of entries to return.

        Returns:
            List of dicts with keys: event_type, timestamp, severity, detail.
        """
        raw = self._chain.entries(last_n)
        result = []
        for e in raw:
            evt = e["event"]
            sev = "CRITICAL" if ("TAMPER" in evt or "VERIFY_FAIL" in evt) else "INFO"
            result.append(
                {
                    "event_type": evt,
                    "timestamp": e["timestamp"],
                    "severity": sev,
                    "detail": e.get("detail", {}),
                }
            )
        return result

    def verify_log_integrity(self) -> bool:
        """Verify in-memory chain is intact and matches the NvM-persisted tip.

        Returns:
            True if the chain is internally consistent and the tip hash matches NvM.
        """
        if not self._chain.verify_integrity():
            return False
        stored_tip = self._nvm.read(_NVM_KEY_CHAIN_TIP)
        if stored_tip is None:
            return True
        if not self._chain._entries:
            return True
        current_tip = self._chain._entries[-1]["hash"]
        return stored_tip == current_tip

    def _persist_chain_tip(self) -> None:
        if self._chain._entries:
            self._nvm.write(_NVM_KEY_CHAIN_TIP, self._chain._entries[-1]["hash"])
