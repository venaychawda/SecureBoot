# SecureBootLab

AUTOSAR Classic Secure Boot — Software Simulation (Phase 1)

## About

SecureBootLab is a software-only simulation of an AUTOSAR Classic ECU secure boot
chain, built to explore and validate automotive secure-boot concepts against
ISO/SAE 21434, UN R155, and AUTOSAR Classic conventions without any target hardware.
It models the full boot chain — Boot ROM → bootloader signature verification →
application image verification → normal operation — plus supporting security
services (HSM, trust anchor / key management, anti-rollback version control,
authenticated recovery, OTA-style update activation/rollback, tamper-evident audit
logging, and debug-interface lockout). Requirements, design docs, and tests live
under `requirements/`, `design/`, and `tests/` and are traced end-to-end in
`requirements/traceability_matrix.md`. A FastAPI backend (`api/`) exposes the
simulation over REST + WebSocket, and `docs/` provides both a standalone
proof-of-concept UI and a live monitor for interactively driving and observing the
simulation — see `UserInfo.md` for a full walkthrough of the live dashboard.

## Standards
- ISO/SAE 21434
- AUTOSAR Classic
- UN R155

## Quick Start

### One-click launch (Windows)

Double-click **`launch.bat`** at the repo root. It will:
1. Create (or reuse) a `.venv` virtual environment.
2. Verify Python 3.11+ and install/update all dependencies from `requirements.txt`.
3. Start the FastAPI backend on `http://localhost:8000`.
4. Start the dashboard file server on `http://localhost:3000`.
5. Open `docs/SecureBoot.html` (the live monitor) in your default browser.

Backend and dashboard servers each run in their own console window — close those
windows (or `Ctrl+C`) to stop them. See `UserInfo.md` for how to use every element
of the live dashboard once it's open.

### Manual steps

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v --tb=short

# Start simulation backend
uvicorn api.main:app --reload --port 8000

# Open PoC dashboard (no server needed)
# Double-click docs/index.html

# Serve full monitor dashboard
python -m http.server 3000 --directory docs
# then open: http://localhost:3000/SecureBoot.html
```

## Phase

**Phase 1 — Simulation (ACTIVE)**  
Phase 2 — Hardware (BLOCKED)

## Repository Layout

```
SecureBoot/
    launch.bat      One-click Windows launcher (venv + deps + backend + dashboard)
    UserInfo.md     Detailed usage guide for docs/SecureBoot.html
    requirements/   Customer, System, Software requirements + Test Plan
    design/         Architecture, HLD, LLD, diagrams
    sim/            Python simulation modules
    api/            FastAPI backend
    docs/           PoC (index.html) and live monitor (SecureBoot.html) dashboards
    tests/          pytest VTC test files
    documents/      ASPICE process documents
```
