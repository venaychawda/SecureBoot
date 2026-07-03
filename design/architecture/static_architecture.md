# Static Architecture — SecureBootLab

**Document ID:** SB-SA-001
**Version:** 0.1
**Date:** 2026-06-09
**ASPICE Process:** SWE.2

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 | 2026-06-09 | [Author TBD] | Initial release |

---

## 1. AUTOSAR Classic Layering Overview

```mermaid
graph LR
    subgraph AppLayer["Application Layer (SWCs)"]
        SBM["SecureBootManager\nSWR-C-001 SWR-C-003\nSWR-C-008 SWR-C-012 SWR-C-014"]
        ATT["AttestationService\nSR-019"]
    end

    subgraph ServiceLayer["BSW Service Layer"]
        BROM["BootROM\nSWR-C-001 SWR-C-002 SWR-C-008\n(immutable ROM stage)"]
        CP["CryptoProvider\nSWR-C-004 SWR-C-005"]
        TAM["TrustAnchorManager\nSR-002 SR-011 SR-020"]
        VM["VersionManager\nSWR-C-006 SWR-C-007"]
        MV["ManifestValidator\nSWR-C-014"]
        RM["RecoveryManager\nSWR-C-009"]
        UM["UpdateManager\nSWR-C-013"]
        SL["SecurityLogger\nSWR-C-010 SWR-C-015"]
        DM["DebugManager\nSWR-C-011 SR-009"]
    end

    subgraph CryptoStack["AUTOSAR Crypto Stack"]
        CSM["CSM\nCrypto Service Manager\n(job state machine)"]
        CryIf["CryIf\nCrypto Interface\n(routing layer)"]
        HSM["HSM\nHardware Security Module\n(ECDSA P-256 / AES-256-GCM / SHA-256)"]
    end

    subgraph DiagInfra["BSW Diagnostic & Persistence"]
        DEM["DEM\nDiagnostic Event Manager\n(INFO / WARNING / CRITICAL)"]
        NvM["NvM\nNon-volatile Memory\n(JSON + atomic write + monotonic counters)"]
    end

    subgraph Foundation["Foundation"]
        CFG["config.py\n(all constants)"]
        ECU["ecu_state.py\n(shared state machine)"]
    end

    BROM --> CP
    BROM --> TAM
    BROM --> VM
    BROM --> ECU
    SBM --> CP
    SBM --> MV
    SBM --> VM
    SBM --> RM
    SBM --> SL
    SBM --> ECU
    CP --> CSM
    TAM --> HSM
    RM --> SL
    RM --> NvM
    RM --> ECU
    UM --> CP
    UM --> VM
    UM --> NvM
    UM --> SL
    SL --> DEM
    SL --> NvM
    DM --> NvM
    DM --> SL
    ATT --> NvM
    ATT --> SL
    CSM --> CryIf
    CryIf --> HSM
    DEM --> NvM
```

---

## 2. Component Dependency Graph (Bottom-Up)

```mermaid
graph TD
    cfg["config.py"]
    ecu["ecu_state.py"]
    nvm["nvm.py"]
    dem["dem.py"]
    hsm["hsm.py"]
    cryif["cryif.py"]
    csm["csm.py"]
    cp["crypto_provider.py"]
    tam["trust_anchor_manager.py"]
    vm["version_manager.py"]
    mv["manifest_validator.py"]
    sl["security_logger.py"]
    brom["boot_rom.py"]
    sbm["secure_boot_manager.py"]
    rm["recovery_manager.py"]
    um["update_manager.py"]
    dm["debug_manager.py"]
    att["attestation_service.py"]

    cfg --> ecu
    cfg --> nvm
    cfg --> dem
    cfg --> hsm
    hsm --> cryif
    cryif --> csm
    csm --> cp
    hsm --> tam
    nvm --> vm
    nvm --> sl
    nvm --> rm
    nvm --> um
    nvm --> dm
    nvm --> att
    dem --> sl
    cp --> brom
    cp --> sbm
    cp --> um
    tam --> brom
    tam --> sbm
    vm --> brom
    vm --> sbm
    vm --> um
    mv --> sbm
    sl --> brom
    sl --> sbm
    sl --> rm
    sl --> um
    sl --> dm
    ecu --> brom
    ecu --> sbm
    ecu --> rm
    brom --> sbm
    rm --> sbm
    att --> sbm
```

---

## 3. AUTOSAR Layer to Module Mapping

| Module | AUTOSAR Equivalent | SWR-C / SR | Layer |
|---|---|---|---|
| `boot_rom.py` | SecureBoot CDD (ROM stage) | SWR-C-001, SWR-C-002, SWR-C-008 | BSW / CDD |
| `secure_boot_manager.py` | SecureBoot SWC | SWR-C-001, SWR-C-003, SWR-C-008, SWR-C-012, SWR-C-014 | Application |
| `crypto_provider.py` | CSM Job Interface | SWR-C-004, SWR-C-005 | BSW Services |
| `trust_anchor_manager.py` | KeyM / CertMgr | SR-002, SR-011, SR-020 | BSW Services |
| `version_manager.py` | Anti-Rollback Counter | SWR-C-006, SWR-C-007 | BSW Services |
| `manifest_validator.py` | SWC Image Meta Parser | SWR-C-014 | BSW Services |
| `recovery_manager.py` | Bootloader Recovery SWC | SWR-C-009 | Application |
| `update_manager.py` | FBL UpdateActivation | SWR-C-013 | Application |
| `security_logger.py` | DEM + HashChainedLog | SWR-C-010, SWR-C-015 | BSW Services |
| `debug_manager.py` | Debug Authentication SWC | SWR-C-011, SR-009 | BSW Services |
| `attestation_service.py` | Measured Boot Reporter | SR-019 | Application |
| `csm.py` | CSM | *(shared)* | AUTOSAR Crypto Stack |
| `cryif.py` | CryIf | *(shared)* | AUTOSAR Crypto Stack |
| `hsm.py` | CryptoDriver / HSM CDD | *(shared)* | MCAL / CDD |
| `dem.py` | DEM | *(shared)* | BSW Services |
| `nvm.py` | NvM | *(shared)* | BSW Services |
| `ecu_state.py` | ECU State Manager | *(shared)* | BSW |
| `config.py` | AUTOSAR Configuration | *(shared)* | BSW Foundation |

---

## 4. Security Boundary Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  HSM TRUST BOUNDARY (hsm.py)                                │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  OEM Root Key   OEM Signing Key   Debug Auth Key    │    │
│  │  (ECDSA P-256 private keys — never exported)        │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────┬──────────────────────────────────┘
                           │ public key PEM only
              ┌────────────▼────────────┐
              │  TrustAnchorManager     │  SR-002, SR-011, SR-020
              │  (public key registry)  │
              └────────────┬────────────┘
                           │ key_id only
              ┌────────────▼────────────┐
              │  CryptoProvider         │  SWR-C-004, SWR-C-005
              │  CryIf → CSM → HSM      │
              └────────────┬────────────┘
                           │ verify result (bool)
   ┌───────────────────────▼─────────────────────────────┐
   │  SecureBootManager / BootROM                         │
   │  SWR-C-001 SWR-C-002 SWR-C-003 SWR-C-008           │
   └───────────────────────┬─────────────────────────────┘
                           │ state transitions
              ┌────────────▼────────────┐
              │  ECUState               │
              │  BootPhase state machine│
              └─────────────────────────┘
```
