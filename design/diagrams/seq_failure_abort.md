# Sequence Diagram — Failure and Abort Flow

**Document ID:** SB-SEQ-002 | **Version:** 0.1 | **Date:** 2026-06-09

Covers: VT-02, VT-04, VT-05, VT-08 | Requirements: SWR-C-002, SWR-C-009, SWR-C-010, SWR-C-014, SWR-C-015

---

## Scenario A — Tampered Bootloader Image (SWR-C-002)

```mermaid
sequenceDiagram
    participant BROM as BootROM
    participant MV as ManifestValidator
    participant CP as CryptoProvider
    participant CSM as CSM
    participant HSM as HSM
    participant SL as SecurityLogger
    participant DEM as DEM
    participant NvM as NvM
    participant RM as RecoveryManager
    participant ECU as ECUState

    BROM->>ECU: transition(BOOTLOADER_VERIFY)
    BROM->>MV: validate(bootloader_manifest)
    MV-->>BROM: Manifest(hash, sig, version=2)
    BROM->>CP: verify_image_signature(tampered_bl_image, sig, oem_signing_key)
    CP->>CSM: verify_signature(tampered_bl_image, sig, oem_signing_key)
    CSM->>HSM: ecdsa_verify(oem_signing_key, tampered_bl_image, sig)
    HSM-->>CSM: False  ← signature mismatch
    CSM-->>CP: False
    CP-->>BROM: valid=False

    BROM->>SL: log_verification_failure(BOOT_STAGE_ROM, SIG_INVALID)
    SL->>DEM: log(CRITICAL, BOOT_BL_SIG_FAIL, SWR-C-002)
    SL->>NvM: write(last_security_event, {stage:ROM, reason:SIG_INVALID})
    BROM->>RM: enter_recovery_mode(reason=SIG_INVALID)
    RM->>ECU: transition(SAFE_STATE, SIG_INVALID)
    RM->>SL: log_boot_event(RECOVERY_ENTERED)
    SL->>DEM: log(CRITICAL, RECOVERY_MODE, SWR-C-009)
    RM->>NvM: increment_counter(boot_failure_count)
    Note over BROM,RM: Boot halts — no unverified code executed (SR-017)
```

---

## Scenario B — Invalid/Malformed Manifest (SWR-C-014)

```mermaid
sequenceDiagram
    participant SBM as SecureBootManager
    participant MV as ManifestValidator
    participant SL as SecurityLogger
    participant DEM as DEM
    participant RM as RecoveryManager
    participant ECU as ECUState

    SBM->>ECU: transition(APPLICATION_VERIFY)
    SBM->>MV: validate(corrupted_manifest)
    MV->>MV: parse() → JSONDecodeError
    MV-->>SBM: ManifestError("parse_failed")

    SBM->>SL: log_verification_failure(APPLICATION, MANIFEST_PARSE_FAIL)
    SL->>DEM: log(CRITICAL, APP_MANIFEST_INVALID, SWR-C-014)
    SBM->>RM: enter_recovery_mode(MANIFEST_INVALID)
    RM->>ECU: transition(SAFE_STATE)
    Note over SBM,RM: Application never executed
```

---

## Scenario C — Tamper Event / Glitch Anomaly (SWR-C-015)

```mermaid
sequenceDiagram
    participant SBM as SecureBootManager
    participant CP as CryptoProvider
    participant HSM as HSM
    participant SL as SecurityLogger
    participant DEM as DEM
    participant RM as RecoveryManager
    participant ECU as ECUState

    Note over HSM: Simulated HSM failure (fault injection / glitch)
    SBM->>CP: verify_image_signature(app_image, sig, key_id)
    CP->>HSM: ecdsa_verify() → HSMError("unavailable")
    CP-->>SBM: CryptoProviderError("hsm_unavailable")

    SBM->>SL: log_tamper_event(context=APPLICATION_VERIFY, {error:hsm_unavailable})
    SL->>DEM: log(CRITICAL, TAMPER_ANOMALY_DETECTED, SWR-C-015)
    SL->>DEM: log(CRITICAL, BOOT_APP_SIG_FAIL, SWR-C-010)
    SBM->>RM: enter_recovery_mode(TAMPER_ANOMALY)
    RM->>ECU: transition(SAFE_STATE)
    Note over SBM: Secure state entered — no execution continues
```
