# Call Stack — SecureBootManager (Most Complex Module)

**Document ID:** SB-CS-001 | **Version:** 0.1 | **Date:** 2026-06-09

`secure_boot_manager.py` is the most complex module: it orchestrates the full verification
chain, coordinates 7 other modules, and handles all failure paths.

---

## Full Call Stack: `SecureBootManager.run_boot_sequence()`

```
SecureBootManager.run_boot_sequence()
│
├── NvM.read(boot_attempt_count)                    [check for prior interruption]
│   └── returns int
│
├── [if count > 0] handle_interruption()            [SWR-C-012]
│   ├── NvM.read(boot_attempt_count)
│   ├── NvM.write(boot_attempt_count, count+1)
│   ├── SecurityLogger.log_boot_event(RESTART_AFTER_INTERRUPTION)
│   │   ├── DEM.log(WARNING, ...)
│   │   └── HashChainedLog.log(...)
│   └── [if count > MAX_BOOT_RETRY_ATTEMPTS]
│       └── ECUState.transition(LOCKED_OUT)         → raises SecureBootError
│
├── ECUState.transition(APPLICATION_VERIFY)
│
├── ManifestValidator.validate(application_manifest) [SWR-C-014]
│   ├── parse(raw) → dict
│   ├── check_required_fields(parsed) → bool
│   └── returns Manifest dataclass
│   └── [on failure] raises ManifestError → caught → RecoveryManager.enter_recovery_mode()
│
├── CryptoProvider.verify_image_signature(          [SWR-C-003]
│     app_image, manifest.signature, manifest.key_id)
│   ├── CSM.verify_signature(image, sig, key_id)
│   │   ├── CryIf.ecdsa_verify(image, sig, key_id)
│   │   │   └── HSM.verify(key_id, image, sig)      [key bytes never leave HSM]
│   │   │       └── private_key.public_key().verify(sig, image, ECDSA(SHA256()))
│   │   └── returns bool
│   └── returns bool
│
├── CryptoProvider.compute_image_hash(app_image)   [SWR-C-004]
│   ├── CSM.compute_hash(app_image)
│   │   ├── CryIf.sha256(app_image)
│   │   │   └── HSM.sha256(app_image)
│   │   │       └── hashes.Hash(SHA256()).finalize()
│   │   └── returns bytes[32]
│   └── [hash != manifest.image_hash] → raises → RecoveryManager.enter_recovery_mode()
│
├── VersionManager.validate_version(               [SWR-C-006, SWR-C-007]
│     APPLICATION, manifest.version)
│   ├── NvM.get_counter(rollback_counter_application)
│   └── returns bool (False → rollback → RecoveryManager.enter_recovery_mode())
│
├── AttestationService.measure_component(          [SR-019]
│     BOOT_STAGE_APPLICATION, app_image)
│   ├── CSM.compute_hash(app_image)
│   │   └── [same path as above]
│   └── NvM.write(attestation_log.APPLICATION, digest)
│
├── SecurityLogger.log_boot_event(APPLICATION_VERIFIED)  [SWR-C-010]
│   ├── DEM.log(INFO, BOOT_APP_VERIFIED, SWR-C-003)
│   └── HashChainedLog.log(APPLICATION_VERIFIED, {...})
│
├── ECUState.transition(NORMAL_OPERATION)          [SWR-C-008]
├── NvM.write(boot_attempt_count, 0)
└── SecurityLogger.log_boot_event(SECURE_BOOT_COMPLETE)
    ├── DEM.log(INFO, SECURE_BOOT_OK)
    └── HashChainedLog.log(SECURE_BOOT_OK)
```

---

## Failure Path Call Stack: `verify_application_image()` → `False`

```
SecureBootManager [detects False from CryptoProvider]
│
├── SecurityLogger.log_verification_failure(APPLICATION, reason)
│   ├── DEM.log(CRITICAL, BOOT_APP_FAIL, SWR-C-010)
│   ├── HashChainedLog.log(VERIFICATION_FAILURE, {stage, reason})
│   └── NvM.write(last_security_event, {stage:APP, reason:...})
│
└── RecoveryManager.enter_recovery_mode(reason)
    ├── ECUState.transition(SAFE_STATE, reason)
    ├── SecurityLogger.log_boot_event(RECOVERY_ENTERED)
    │   └── DEM.log(CRITICAL, RECOVERY_MODE, SWR-C-009)
    └── NvM.increment_counter(boot_failure_count)
```

---

## Module Dependency Depth (SecureBootManager)

| Depth | Module | Called Via |
|---|---|---|
| 0 | `secure_boot_manager.py` | Entry point |
| 1 | `manifest_validator.py` | Direct call |
| 1 | `crypto_provider.py` | Direct call |
| 1 | `version_manager.py` | Direct call |
| 1 | `recovery_manager.py` | Direct call (failure path) |
| 1 | `attestation_service.py` | Direct call |
| 1 | `security_logger.py` | Direct call |
| 1 | `ecu_state.py` | Direct (shared state) |
| 1 | `nvm.py` | Direct |
| 2 | `csm.py` | Via `crypto_provider` |
| 2 | `dem.py` | Via `security_logger` |
| 3 | `cryif.py` | Via `csm` |
| 4 | `hsm.py` | Via `cryif` |
