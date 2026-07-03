"""All tunable constants for SecureBootLab simulation.

No magic numbers anywhere else in the codebase.
"""

# ---- NvM ---------------------------------------------------------------
NVM_STORE_PATH = "sim/nvm_store.json"

# NvM block keys
NVM_KEY_BOOT_COUNTER = "boot_counter"
NVM_KEY_FIRMWARE_VERSION_BL = "fw_version_bootloader"
NVM_KEY_FIRMWARE_VERSION_APP = "fw_version_application"
NVM_KEY_ROLLBACK_COUNTER_BL = "rollback_counter_bootloader"
NVM_KEY_ROLLBACK_COUNTER_APP = "rollback_counter_application"
NVM_KEY_SECURE_BOOT_ENABLED = "secure_boot_enabled"
NVM_KEY_LIFECYCLE_STATE = "lifecycle_state"
NVM_KEY_DEBUG_LOCKED = "debug_locked"
NVM_KEY_ATTESTATION_LOG = "attestation_log"

# ---- DEM / Audit Log ---------------------------------------------------
MAX_AUDIT_ENTRIES = 1000

# ---- Crypto ------------------------------------------------------------
# HSM key identifiers
HSM_KEY_ID_OEM_ROOT = "oem_root_key"
HSM_KEY_ID_OEM_SIGNING = "oem_signing_key"
HSM_KEY_ID_BOOTLOADER = "bootloader_key"

# Approved algorithms (SR-005)
APPROVED_HASH_ALGORITHM = "SHA-256"
APPROVED_SIGNATURE_ALGORITHM = "ECDSA-P256"

# ---- Version / Anti-rollback -------------------------------------------
# Minimum acceptable firmware version floor (SWR-C-007)
FIRMWARE_VERSION_FLOOR_BL = 1
FIRMWARE_VERSION_FLOOR_APP = 1

# ---- Lifecycle States --------------------------------------------------
LIFECYCLE_DEVELOPMENT = "DEVELOPMENT"
LIFECYCLE_PRODUCTION = "PRODUCTION"
LIFECYCLE_EOL = "EOL"

# ---- Secure Boot -------------------------------------------------------
# Maximum retry attempts before permanent lockout
MAX_BOOT_RETRY_ATTEMPTS = 3

# Boot stage identifiers for chain-of-trust logging
BOOT_STAGE_ROM = "BOOT_ROM"
BOOT_STAGE_BOOTLOADER = "BOOTLOADER"
BOOT_STAGE_APPLICATION = "APPLICATION"

# ---- Debug -------------------------------------------------------------
# JTAG/SWD access gate (SR-014)
DEBUG_GATE_ALGORITHM = "ECDSA-P256"
HSM_KEY_ID_DEBUG_AUTH = "debug_auth_key"

# ---- Attestation -------------------------------------------------------
ATTESTATION_BACKEND_URL = "http://localhost:9000/attestation"  # sim only

# ---- API ---------------------------------------------------------------
API_HOST = "0.0.0.0"
API_PORT = 8000
DASHBOARD_ORIGIN = "http://localhost:3000"
WEBSOCKET_PATH = "/ws/events"
