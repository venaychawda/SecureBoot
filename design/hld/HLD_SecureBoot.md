# High-Level Design — SecureBootLab

**Document ID:** SB-HLD-001
**Version:** 0.1
**Date:** 2026-06-09
**Author:** [Author TBD]
**ASPICE Process:** SWE.2

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-06-09 | [Author TBD] | Initial release |

---

## 1. Purpose & Scope

This document defines the high-level software architecture for the SecureBootLab AUTOSAR Classic
Secure Boot simulation (Phase 1). It covers the Python-based simulation of all modules involved in
hardware-root-of-trust establishment, cryptographic image verification, anti-rollback enforcement,
authenticated recovery, OTA update activation, debug access control, and security event logging.

**In scope:** Software simulation of the full secure boot chain from Boot ROM through application
launch, as specified by SWR-C-001 to SWR-C-015. All 11 sim/ modules from `requirements/sim.txt`.

**Out of scope:** Physical hardware (OTP fuses, JTAG hardware, real HSM silicon), production ECU
firmware, Phase 2 hardware integration. Those are deferred to Phase 2.

---

## 2. System Context

The system implements System Requirements SR-001 to SR-020 as defined in
`requirements/SystemRequirement.txt`, derived from Customer Requirements CR-001 to CR-010 in
`requirements/CustomerRequirement.txt`. All 15 software requirements SWR-C-001 to SWR-C-015 in
`requirements/SoftwareRequirement_Classic.txt` are allocated to simulation modules.

External interfaces:

| Interface | Direction | Description |
|---|---|---|
| **FastAPI REST** (`api/main.py`) | Dashboard → Simulation | Test scenario trigger, ECU state query, event log query |
| **WebSocket** (`/ws/events`) | Simulation → Dashboard | Real-time DEM event stream and ECU state changes |
| **NvM JSON store** (`sim/nvm_store.json`) | Simulation ↔ Filesystem | Persistent boot counters, version floors, security events |
| **OEM OTA Backend (sim)** | External → UpdateManager | Firmware package + ECDSA signature delivery |

---

## 3. Component Overview

| Module | Role | SWR-C / SR |
|---|---|---|
| `config.py` | Central constants registry — all timeouts, key IDs, NvM keys, retry limits | All |
| `ecu_state.py` | Shared ECU boot phase state machine (`BootPhase` enum, lifecycle) | All |
| `hsm.py` | HSM simulator — ECDSA P-256 sign/verify, AES-256-GCM, SHA-256; key bytes never exported | Shared |
| `dem.py` | AUTOSAR DEM — severity-classified event log + HashChainedLog for tamper evidence | Shared |
| `nvm.py` | AUTOSAR NvM — JSON-backed store, atomic write, monotonic counter API | Shared |
| `cryif.py` | AUTOSAR CryIf — routing layer, delegates all crypto to HSM | Shared |
| `csm.py` | AUTOSAR CSM — IDLE→ACTIVE→FINISHED/FAILED job state machine | Shared |
| `boot_rom.py` | Immutable hardware root of trust; verifies bootloader before execution | SWR-C-001, SWR-C-002, SWR-C-008 |
| `secure_boot_manager.py` | Orchestrates full boot sequence; verifies app; handles interruption/retry | SWR-C-001, SWR-C-003, SWR-C-008, SWR-C-012, SWR-C-014 |
| `crypto_provider.py` | Policy-compliant SHA-256/ECDSA-P256 ops; enforces algorithm selection (SR-005) | SWR-C-004, SWR-C-005 |
| `trust_anchor_manager.py` | OEM root-of-trust key registry; prevents unauthorized key modification; supports rotation | SR-002, SR-011, SR-020 |
| `version_manager.py` | Anti-rollback — validates version counters against NvM-stored floors | SWR-C-006, SWR-C-007 |
| `manifest_validator.py` | Parses and validates firmware manifest metadata and embedded hash/sig fields | SWR-C-014 |
| `recovery_manager.py` | Authenticated recovery mode; rejects unsigned recovery images | SWR-C-009 |
| `update_manager.py` | OTA update authentication + atomic activation with rollback fallback | SWR-C-013 |
| `security_logger.py` | Boot failure and tamper event recording to DEM + HashChainedLog in NvM | SWR-C-010, SWR-C-015 |
| `debug_manager.py` | JTAG/SWD lock enforcement in production lifecycle; cryptographic debug gating | SWR-C-011, SR-009 |
| `attestation_service.py` | Measured boot — records component hashes for backend attestation | SR-019 |

---

## 4. Inter-Component Interfaces

| Caller | Callee | Key Operations |
|---|---|---|
| `boot_rom` | `trust_anchor_manager` | `get_oem_public_key()` |
| `boot_rom` | `crypto_provider` | `verify_image_signature()`, `compute_image_hash()` |
| `boot_rom` | `manifest_validator` | `validate()` |
| `boot_rom` | `version_manager` | `validate_version()` |
| `boot_rom` | `security_logger` | `log_boot_event()`, `log_verification_failure()` |
| `secure_boot_manager` | `crypto_provider` | `verify_image_signature()`, `compute_image_hash()` |
| `secure_boot_manager` | `manifest_validator` | `validate()` |
| `secure_boot_manager` | `version_manager` | `validate_version()`, `commit_version()` |
| `secure_boot_manager` | `recovery_manager` | `enter_recovery_mode()` |
| `secure_boot_manager` | `attestation_service` | `measure_component()` |
| `crypto_provider` | `csm` | `verify_signature()`, `compute_hash()` |
| `csm` | `cryif` | `ecdsa_verify()`, `sha256()` |
| `cryif` | `hsm` | `verify()`, `sha256()`, `sign()` |
| `update_manager` | `crypto_provider` | `verify_image_signature()` |
| `update_manager` | `version_manager` | `validate_version()`, `commit_version()` |
| `recovery_manager` | `crypto_provider` | `verify_image_signature()` (recovery image) |
| `debug_manager` | `hsm` | `verify()` (debug credential) |
| `attestation_service` | `csm` | `compute_hash()` (per-component hash) |
| All modules | `security_logger` | `log_boot_event()`, `log_tamper_event()`, `log_verification_failure()` |
| `security_logger` | `dem` | `log(severity, description, swr_ref)` |
| `security_logger` | `nvm` | `write(security_event_key)` |
| All stateful modules | `nvm` | `read()`, `write()`, `get_counter()`, `increment_counter()` |
| All modules | `ecu_state` | `transition()`, `boot_phase`, `lifecycle` |

---

## 5. Security Architecture

### 5.1 Trust Zones

```
[ OTP / e-Fuse (Hardware — simulated as NvM flag) ]
      │
[ Boot ROM — immutable first-stage code (boot_rom.py) ]
      │  verifies with OEM public key from TrustAnchorManager
[ Bootloader Image — verified before execution (SWR-C-002) ]
      │  verifies application image signature (SWR-C-003)
[ Application Image — verified before launch ]
      │  post-boot
[ NORMAL_OPERATION — ECUState (SWR-C-008 chain complete) ]
```

### 5.2 Key Hierarchy

| Key ID | Type | Storage | Purpose |
|---|---|---|---|
| `oem_root_key` | ECDSA P-256 private | HSM only — never exported | Signs OEM signing certificates / intermediate keys |
| `oem_signing_key` | ECDSA P-256 private | HSM only — never exported | Signs bootloader and application images |
| `bootloader_key` | ECDSA P-256 private | HSM only — never exported | Alternative bootloader signing key |
| `debug_auth_key` | ECDSA P-256 private | HSM only — never exported | Authenticates cryptographic debug access (SR-014) |
| Public keys (all above) | ECDSA P-256 public | TrustAnchorManager (exported via PEM) | Verification in BootROM / SecureBootManager |

Raw key bytes never leave `hsm.py`. All signing operations are invoked via `hsm.sign(key_id, data)`;
all verification via `hsm.verify(key_id, data, sig)`. `TrustAnchorManager` retrieves only the public
key PEM for external callers.

### 5.3 Lifecycle Roles

| Lifecycle State | Debug Access | Secure Boot | Key Rotation Permitted |
|---|---|---|---|
| `DEVELOPMENT` | Open (no credential required) | Optional | Yes |
| `PRODUCTION` | Cryptographically gated (SWR-C-011) | Mandatory (SR-009) | Authorized only (SR-002) |
| `EOL` | Locked (no access) | Mandatory | No |

### 5.4 Threat Mitigations

| Threat | Mitigation | Requirement |
|---|---|---|
| Unsigned firmware execution | ECDSA P-256 signature verification on every image | SWR-C-002, SWR-C-003 |
| Firmware downgrade / rollback | Monotonic version counter enforced in NvM | SWR-C-006, SWR-C-007 |
| Replay of old firmware package | Same version counter provides freshness control | SR-012 |
| Tampered manifest / metadata | ManifestValidator rejects malformed metadata | SWR-C-014 |
| Key extraction from HSM | Key bytes never leave `hsm.py`; public keys only exported | SR-011, SR-002 |
| Debug bypass in production | DebugManager enforces cryptographic gate; JTAG locked | SWR-C-011, SR-009 |
| Power loss during verification | BootROM detects in-progress flag; restarts from scratch | SWR-C-012, SR-008 |
| Unsigned recovery flashing | RecoveryManager requires authenticated image | SWR-C-009, SR-017 |
| Boot log tampering | HashChainedLog with SHA-256 chain linking | SWR-C-010 |

---

## 6. Error & Failure Handling Strategy

All security verification failures follow this abort sequence:

1. `CryptoProvider` / `ManifestValidator` returns `valid=False` or raises exception
2. `SecureBootManager` / `BootROM` calls `security_logger.log_verification_failure(stage, reason)`
3. `SecurityLogger` → `DEM.log(CRITICAL, event_id, swr_ref)` — tamper event if anomaly detected
4. `SecurityLogger` → `NvM.write(last_security_event, ...)` — persists to protected storage
5. `RecoveryManager.enter_recovery_mode(reason)` — transitions ECU to `SAFE_STATE`
6. ECU remains in `SAFE_STATE` or `LOCKED_OUT` — no unverified code is ever executed

Power-loss recovery (SWR-C-012):
- On power restore, `BootROM` reads `NvM.boot_attempt_count`
- If `> 0`, full re-verification from the beginning (no partial state)
- If `> MAX_BOOT_RETRY_ATTEMPTS`, ECU transitions to `LOCKED_OUT`

---

## 7. Constraints & Assumptions

| Constraint | Detail |
|---|---|
| Simulation only | No real OTP fuse blow, no physical JTAG lock, no real HSM silicon |
| Crypto library | `cryptography` (PyCA) provides ECDSA P-256 and AES-256-GCM — not `hashlib` for signing |
| NvM | Simulated as a JSON file; atomic writes use write-then-rename (`os.replace`) |
| Key management | Keys generated in-memory per test session; not persisted between sessions |
| Fault injection | Simulated via `hsm.simulate_failure(True)` and deliberate tamper fixtures in `conftest.py` |
| Transport | Dashboard → API over localhost; no real vehicle bus (CAN, Ethernet) in simulation |
| CRL / OCSP | Not implemented in Phase 1; certificate revocation is a Phase 2 concern |
| Thread safety | All modules assume single-threaded execution in simulation; no mutex needed in Phase 1 |
