# Dynamic Architecture — SecureBootLab

**Document ID:** SB-DA-001
**Version:** 0.1
**Date:** 2026-06-09
**ASPICE Process:** SWE.2

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-06-09 | [Author TBD] | Initial release |

---

## 1. Primary Happy-Path: Normal Secure Boot Sequence

```mermaid
sequenceDiagram
    participant PWR as Power Supply
    participant BROM as BootROM
    participant TAM as TrustAnchorManager
    participant CP as CryptoProvider
    participant CSM as CSM
    participant HSM as HSM
    participant MV as ManifestValidator
    participant VM as VersionManager
    participant SBM as SecureBootManager
    participant SL as SecurityLogger
    participant DEM as DEM
    participant NvM as NvM
    participant ECU as ECUState

    PWR->>BROM: power_on()
    BROM->>ECU: transition(ROM_INIT)
    BROM->>NvM: read(secure_boot_enabled)
    NvM-->>BROM: True
    BROM->>TAM: get_oem_public_key(HSM_KEY_ID_OEM_SIGNING)
    TAM->>HSM: get_public_key_pem(key_id)
    HSM-->>TAM: public_key_pem
    TAM-->>BROM: key_id reference

    Note over BROM,CP: Stage 1 — Bootloader Verification (SWR-C-001, SWR-C-002)
    BROM->>ECU: transition(BOOTLOADER_VERIFY)
    BROM->>MV: validate(bootloader_manifest)
    MV-->>BROM: Manifest(hash, sig, version)
    BROM->>CP: verify_image_signature(bl_image, sig, key_id)
    CP->>CSM: verify_signature(bl_image, sig, key_id)
    CSM->>HSM: ecdsa_verify(key_id, bl_image, sig)
    HSM-->>CSM: True
    CSM-->>CP: FINISHED / True
    CP-->>BROM: valid=True
    BROM->>CP: compute_image_hash(bl_image)
    CP->>CSM: compute_hash(bl_image)
    CSM->>HSM: sha256(bl_image)
    HSM-->>CSM: digest
    CSM-->>CP: digest
    CP-->>BROM: hash_ok=True
    BROM->>VM: validate_version(BOOTLOADER, manifest.version)
    VM->>NvM: get_counter(rollback_counter_bootloader)
    NvM-->>VM: current_floor
    VM-->>BROM: no_rollback=True
    BROM->>SL: log_boot_event(BOOTLOADER_VERIFIED)
    SL->>DEM: log(INFO, BOOT_BL_VERIFIED, SWR-C-002)

    Note over SBM,CP: Stage 2 — Application Verification (SWR-C-003, SWR-C-014)
    BROM->>SBM: handoff_to_bootloader()
    SBM->>ECU: transition(APPLICATION_VERIFY)
    SBM->>MV: validate(application_manifest)
    MV-->>SBM: Manifest(hash, sig, version)
    SBM->>CP: verify_image_signature(app_image, sig, key_id)
    CP->>CSM: verify_signature(app_image, sig, key_id)
    CSM->>HSM: ecdsa_verify(key_id, app_image, sig)
    HSM-->>CSM: True
    CSM-->>CP: FINISHED / True
    CP-->>SBM: valid=True
    SBM->>VM: validate_version(APPLICATION, manifest.version)
    VM->>NvM: get_counter(rollback_counter_application)
    NvM-->>VM: current_floor
    VM-->>SBM: no_rollback=True
    SBM->>SL: log_boot_event(APPLICATION_VERIFIED)
    SL->>DEM: log(INFO, BOOT_APP_VERIFIED, SWR-C-003)
    SBM->>ECU: transition(NORMAL_OPERATION)
    SBM->>SL: log_boot_event(SECURE_BOOT_COMPLETE)
    SL->>DEM: log(INFO, SECURE_BOOT_OK)
```

---

## 2. Failure / Abort Flow — Signature Verification Failure

```mermaid
sequenceDiagram
    participant BROM as BootROM
    participant CP as CryptoProvider
    participant CSM as CSM
    participant HSM as HSM
    participant SL as SecurityLogger
    participant DEM as DEM
    participant NvM as NvM
    participant RM as RecoveryManager
    participant ECU as ECUState

    Note over BROM,CP: Tampered or unsigned bootloader detected (SWR-C-002)
    BROM->>CP: verify_image_signature(tampered_bl, sig, key_id)
    CP->>CSM: verify_signature(tampered_bl, sig, key_id)
    CSM->>HSM: ecdsa_verify(key_id, tampered_bl, sig)
    HSM-->>CSM: False
    CSM-->>CP: FINISHED / False
    CP-->>BROM: valid=False

    BROM->>SL: log_verification_failure(BOOTLOADER, reason=SIG_INVALID)
    SL->>DEM: log(CRITICAL, BOOT_BL_SIG_FAIL, SWR-C-002)
    SL->>NvM: write(last_security_event, SIG_FAIL)

    BROM->>RM: enter_recovery_mode(reason=SIG_INVALID)
    RM->>ECU: transition(SAFE_STATE, reason=SIG_INVALID)
    RM->>SL: log_boot_event(RECOVERY_ENTERED)
    SL->>DEM: log(CRITICAL, RECOVERY_MODE, SWR-C-009)
    RM->>NvM: write(boot_failure_count, count+1)

    Note over RM: Boot halts — no unverified code executed (SR-017)
```

---

## 3. Recovery Flow — Power Loss During Verification

```mermaid
sequenceDiagram
    participant PWR as Power Supply
    participant BROM as BootROM
    participant NvM as NvM
    participant SL as SecurityLogger
    participant DEM as DEM
    participant ECU as ECUState
    participant SBM as SecureBootManager

    Note over PWR,BROM: Power restored after interruption during prior boot (SR-008, SWR-C-012)
    PWR->>BROM: power_on()
    BROM->>ECU: transition(ROM_INIT)
    BROM->>NvM: read(boot_attempt_count)
    NvM-->>BROM: attempt_count (>0 indicates prior interruption)
    BROM->>SL: log_boot_event(RECOVERY_RESTART_DETECTED)
    SL->>DEM: log(WARNING, POWER_LOSS_RECOVERY, SWR-C-012)

    Note over BROM: Full re-verification from scratch — no partial state (SR-008)
    BROM->>NvM: write(boot_attempt_count, attempt_count+1)
    BROM->>ECU: transition(BOOTLOADER_VERIFY)

    Note over BROM,SBM: Full secure boot chain re-executed (same as normal boot)
    BROM->>SBM: run_full_verification()

    alt MAX_BOOT_RETRY_ATTEMPTS exceeded
        BROM->>ECU: transition(LOCKED_OUT)
        BROM->>SL: log_verification_failure(ALL_STAGES, RETRY_EXCEEDED)
        SL->>DEM: log(CRITICAL, LOCKOUT, SR-008)
    else Verification succeeds
        SBM->>ECU: transition(NORMAL_OPERATION)
        BROM->>NvM: write(boot_attempt_count, 0)
    end
```

---

## 4. OTA Update Authentication Flow

```mermaid
sequenceDiagram
    participant OTA as OEM OTA Backend
    participant API as FastAPI (api/main.py)
    participant UM as UpdateManager
    participant CP as CryptoProvider
    participant CSM as CSM
    participant HSM as HSM
    participant VM as VersionManager
    participant NvM as NvM
    participant SL as SecurityLogger
    participant DEM as DEM
    participant SBM as SecureBootManager
    participant ECU as ECUState

    OTA->>API: POST /update/upload {package, signature}
    API->>UM: validate_update_package(package, signature)

    Note over UM,CP: Step 1 — Authenticate update package (SWR-C-013)
    UM->>CP: verify_image_signature(package, signature, HSM_KEY_ID_OEM_SIGNING)
    CP->>CSM: verify_signature(package, signature, key_id)
    CSM->>HSM: ecdsa_verify()
    HSM-->>CSM: True
    CSM-->>CP: True
    CP-->>UM: valid=True

    Note over UM,VM: Step 2 — Anti-rollback check (SWR-C-006, SWR-C-007)
    UM->>VM: validate_version(APPLICATION, package.version)
    VM->>NvM: get_counter(rollback_counter_application)
    NvM-->>VM: current_floor
    VM-->>UM: no_rollback=True

    Note over UM,NvM: Step 3 — Atomic activation (SR-010)
    UM->>NvM: write(update_pending, True)
    UM->>NvM: write(staged_image, package)
    UM->>SL: log_boot_event(UPDATE_STAGED)
    SL->>DEM: log(INFO, UPDATE_STAGED, SWR-C-013)
    UM->>VM: commit_version(APPLICATION, package.version)
    VM->>NvM: write(rollback_counter_application, new_version)
    UM->>NvM: write(update_pending, False)
    UM-->>API: UpdateResult(success=True)
    API-->>OTA: 200 OK

    Note over SBM: Next boot — full re-verification of new image
    SBM->>ECU: transition(APPLICATION_VERIFY)
    SBM->>CP: verify_image_signature(new_app_image, sig, key_id)
```
