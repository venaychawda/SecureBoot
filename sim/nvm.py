"""NvM simulator — JSON-backed persistent key-value store with monotonic counters.

Drop-in stub for AUTOSAR NvM. Atomic write via write-then-rename.
"""
import json
import os
from pathlib import Path
from typing import Any

from sim.config import NVM_STORE_PATH


class NvMError(Exception):
    pass


class NvM:
    """Simulates AUTOSAR NvM using a JSON file with atomic write semantics."""

    _DEFAULT_PATH = Path(NVM_STORE_PATH)

    def __init__(self, path: str | None = None) -> None:
        self._path = Path(path) if path else self._DEFAULT_PATH
        self._store: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._store = json.loads(self._path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._store = {}

    def flush(self) -> None:
        """Atomic write: write to .tmp then rename."""
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._store, indent=2), encoding="utf-8")
        os.replace(tmp, self._path)

    def read(self, key: str, default: Any = None) -> Any:
        """Read a value from NvM.

        Args:
            key: NvM block identifier.
            default: Value returned if key absent.

        Returns:
            Stored value or default.
        """
        return self._store.get(key, default)

    def write(self, key: str, value: Any) -> None:
        """Write a value to NvM and flush.

        Args:
            key: NvM block identifier.
            value: Value to persist.
        """
        self._store[key] = value
        self.flush()

    def increment_counter(self, key: str) -> int:
        """Increment a monotonic counter by 1 and return new value.

        Args:
            key: Counter identifier.

        Returns:
            New counter value.

        Raises:
            NvMError: On overflow.
        """
        current = self._store.get(key, 0)
        if current >= 2**63 - 1:
            raise NvMError("counter_overflow")
        new_val = current + 1
        self._store[key] = new_val
        self.flush()
        return new_val

    def get_counter(self, key: str) -> int:
        """Return current counter value without incrementing.

        Args:
            key: Counter identifier.

        Returns:
            Current counter value (0 if never set).
        """
        return int(self._store.get(key, 0))

    def reset_to_defaults(self) -> None:
        """Clear all NvM contents and flush."""
        self._store = {}
        self.flush()
