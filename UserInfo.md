# SecureBoot.html — User Guide

This document explains every GUI element in `docs/SecureBoot.html` (the **Live
Monitor**), what it does under the hood, what result to expect when you use it, and
how to use it to validate the SecureBootLab AUTOSAR Classic secure-boot simulation
against its requirements (`requirements/SoftwareRequirement_Classic.txt`,
`requirements/TestCase.txt`, `requirements/traceability_matrix.md`).

It is written directly against the current implementation (`sim/*.py`, `api/*.py`),
not just against the UI, so that "expected result" statements below are accurate —
including a few places where the live backend behaves differently than the button
label might suggest. Those are called out explicitly in **⚠ Note** boxes.

---

## 1. Starting the Live Monitor

`SecureBoot.html` is **not** a standalone file — it calls a REST API and opens a
WebSocket against a FastAPI backend on `http://localhost:8000`, and it must itself be
served from `http://localhost:3000` (not opened directly as a `file://` URL), because
the backend's CORS policy only allows the origin `http://localhost:3000`
(`sim/config.py: DASHBOARD_ORIGIN`). Opening the HTML file directly will cause every
`fetch()` call to fail with a CORS error even though the backend is running.

**Easiest path:** double-click `launch.bat` at the repo root. It creates/reuses
`.venv`, installs `requirements.txt`, starts the backend on port 8000, starts a static
file server for `docs/` on port 3000, and opens `SecureBoot.html` automatically.

**Manual path:**
```bash
uvicorn api.main:app --reload --port 8000        # terminal 1
python -m http.server 3000 --directory docs      # terminal 2
# then open http://localhost:3000/SecureBoot.html
```

If the backend is not reachable, a full-screen **"⚡ Backend Offline"** overlay
appears with the exact `uvicorn` command to run and a **▶ Connect Now** button to
retry the WebSocket connection once the backend is up.

---

## 2. Layout at a glance

```
┌─────────────────────────────────────────────────────────────────────┐
│ 🟢 Live Monitor banner                                               │
├─────────────────────────────────────────────────────────────────────┤
│ ◆ SecureBootLab   AUTOSAR Classic · Live Backend    [WS●] [LIFECYCLE]│
├───────────────────────────┬─────────────────────────────────────────┤
│ Panel 1: ECU State Monitor │ Panel 2: Live Operations Console        │
│ (boot-phase flow diagram)  │ (buttons + API terminal)                │
├───────────────────────────┼─────────────────────────────────────────┤
│ Panel 3: Test Scenario     │ Panel 4: Security Event Log             │
│ Runner (VT-01 … VT-22)     │ (DEM events)                            │
└───────────────────────────┴─────────────────────────────────────────┘
```

Everything on the page is driven by two data sources: **REST calls** (buttons trigger
`fetch()` calls to `API_BASE = http://localhost:8000`) and **one WebSocket**
(`ws://localhost:8000/ws/events`) that pushes `ecu_state`, `boot_result`, and
`vtc_result` messages as they happen.

---

## 3. Header bar

| Element | Meaning |
|---|---|
| **WS status chip** (top right, "Connecting…" / "Connected" / "Disconnected") | Live WebSocket connection state. Amber pulsing = connecting, green = connected, red = disconnected (click it to force a reconnect attempt). Auto-reconnects with backoff (2s → up to 15s) if the backend drops. |
| **Lifecycle badge** (`DEVELOPMENT` / `PRODUCTION` / `EOL`) | Reflects `ecu.lifecycle` from the backend's single shared `ECUState` instance. |

**⚠ Note:** the lifecycle badge will show **`DEVELOPMENT` for the entire session** —
no button in this dashboard changes it, because the shared simulation instance behind
`/ecu/state` is always constructed with the default `LifecycleState.DEVELOPMENT`
(`api/main.py: _create_sim()`). This matters because `DebugManager` only locks the
debug interface and enforces the debug-auth credential in `PRODUCTION`/`EOL`
(`SR-014`) — in `DEVELOPMENT` the debug interface is always reported `OPEN`. To
exercise the `PRODUCTION` debug-lock behaviour (VT-06, VT-09), use the **Test
Scenario Runner** (Panel 3), which builds an isolated sim and sets lifecycle to
`PRODUCTION` internally for those specific VTCs — not the live console.

---

## 4. Panel 1 — ECU State Monitor

Live view of the shared backend `ECUState`, updated every time the WebSocket
broadcasts an `ecu_state` message (which happens after almost every operation in
Panel 2).

### 4.1 Boot phase flow diagram

Five main phases, connected top-to-bottom, light up amber (active/in-progress), green
(success), or stay dim (not yet reached):

| Phase | Icon | Meaning |
|---|---|---|
| `POWER_OFF` | ⚫ | Idle / initial state, or after **Reset ECU**. |
| `ROM_INIT` | 🔌 | Boot ROM has started executing. |
| `BOOTLOADER_VERIFY` | 🔑 | ECDSA signature check of the bootloader stage. |
| `APPLICATION_VERIFY` | 🔒 | Hash + signature + version check of the application image. |
| `NORMAL_OPERATION` | ✅ | Full chain of trust verified — ECU is running (turns **green**). |

Below the main chain, three side-path nodes represent failure/alternate outcomes and
light up instead of (not in addition to) the main chain when reached:

| Side phase | Icon | Meaning | Colour |
|---|---|---|---|
| `SAFE_STATE` | 🛑 | Verification failed at some stage; ECU refuses to run untrusted code. | red |
| `RECOVERY_MODE` | 🔧 | ECU is in an authenticated recovery/service session. | blue |
| `LOCKED_OUT` | 🔐 | Boot retry counter exceeded `MAX_BOOT_RETRY_ATTEMPTS` (3) — permanent lockout until **Reset ECU**. | amber |

**⚠ Note:** `RecoveryManager.enter_recovery_mode()` (used by the **Enter Recovery**
button, §5.2) transitions the ECU to **`SAFE_STATE`**, not `RECOVERY_MODE`, in the
current implementation. So clicking **Enter Recovery** lights up the `SAFE_STATE`
node (red), not the `RECOVERY_MODE` node (blue) — this is expected, not a bug in the
dashboard.

### 4.2 Property tiles

| Tile | Source | Expected values |
|---|---|---|
| **Boot Attempts** | `boot_attempt_count` | Increments by 1 every time **Start Boot Sequence** runs; only reset by **Reset ECU**. |
| **Lifecycle** | `lifecycle` | Always `DEVELOPMENT` via this console (see §3). |
| **Secure Boot** | `secure_boot_enabled` | `ENABLED` (green) normally; the sim always keeps this `True` in DEVELOPMENT. |
| **Debug Interface** | `debug_locked` | `OPEN` (green) in DEVELOPMENT lifecycle; would show `LOCKED` (red) only in PRODUCTION/EOL, which this console never sets (see §3). |

### 4.3 Attestation Hash row

**⚠ Note:** this row is present in the HTML but is **not wired up** in the current
build — it stays hidden (`display:none`) for the whole session, because
`ECUState.to_dict()` (the payload sent over the WebSocket / `GET /ecu/state`) does not
include `attestation_hash`, and no script in `SecureBoot.html` ever un-hides or
populates it. `attestation_hash` *is* computed internally by `SecureBootManager` and
`AttestationService` — to see a measured-boot digest, run **VT-10** in the Test
Scenario Runner (Panel 3) and inspect its result detail (`digest_length`) or query
`/diagnostics/*` / call `AttestationService` directly via a script. This does not
affect VTC pass/fail, only what this panel visually displays.

---

## 5. Panel 2 — Live Operations Console

Top of the panel shows the raw WebSocket URL and connection state (mirrors the header
chip). Below it, three groups of buttons; at the bottom, an **API Terminal** that logs
every request/response pair (grey = request line, green = success response, red =
error response). Use **⊘ Clear** above the terminal to wipe it (client-side only).

### 5.1 Boot & ECU

| Button | Calls | Expected result |
|---|---|---|
| **📦 Provision App Image** | `POST /dev/provision-app-image` | Writes a valid OEM-signed v2 application image into NvM key `active_application_image`, plus sets `pending_update_version = 3`. Logs `PROVISION_OK` in the API terminal. **This does not, by itself, change what "Start Boot Sequence" does** — see the note below. |
| **▶ Start Boot Sequence** | `POST /boot/start` → `BootROM.power_on()` | Almost always reaches **`NORMAL_OPERATION`** (green) immediately, because `BootROM.power_on()` only checks NvM key `active_bootloader_image` (never written by any button here); if absent it assumes "the factory-provisioned bootloader is valid" and proceeds straight through to `NORMAL_OPERATION`. Each click increments **Boot Attempts**. |
| **↺ Reset ECU** | `POST /ecu/reset` | Returns the ECU to `POWER_OFF`, zeroes `boot_attempt_count`, clears `last_failure_reason`. Use this between test runs. |
| **⟳ Refresh State** | `GET /ecu/state` | Re-pulls current state (useful if you suspect the WebSocket missed an update). |

**⚠ Important nuance — "Provision App Image" vs "Start Boot Sequence":**
The REST endpoint behind **Start Boot Sequence** (`/boot/start`) calls
`BootROM.power_on()`, which validates the *bootloader* stage only (and only if one was
explicitly stored). It does **not** read `active_application_image`, so provisioning
first has no visible effect on this button's outcome. The module that *does* enforce
"no application image ⇒ `SAFE_STATE`" is `SecureBootManager.run_boot_sequence()`
(`SWR-C-003`, `SWR-C-014`) — that logic is exercised by the **Test Scenario Runner**
(VT-02 = no image → `SAFE_STATE`; VT-13 = provisioned image → `NORMAL_OPERATION`), not
by this console button. If you want to see a *failed* boot from this console, use
**Reproducing a lockout** in §7.3 instead.

### 5.2 Firmware Operations

| Button | Calls | Expected result |
|---|---|---|
| **⬆ Activate Test Update** | `GET /dev/test-image` then `POST /update/activate` | Fetches a fresh OEM-signed v2 test image from the backend HSM, then activates it: backs up the current `active_application_image` to `previous_application_image`, writes the new image, and commits version 2 in `VersionManager`. First click: `activated: true`. |
| **⏮ Rollback Update** | `POST /update/rollback` | Restores `previous_application_image` into `active_application_image`. |
| **🛠 Enter Recovery** | `POST /recovery/enter` | Transitions ECU to `SAFE_STATE` (see §4.1 note) and logs `RECOVERY_MODE_ENTERED`. |
| **💾 Flash Test Image** | `GET /dev/test-image` then `POST /recovery/flash` | Verifies the OEM signature and, if valid, writes a v1 image into `active_application_image` via `RecoveryManager`. Always succeeds because the test image is always correctly signed by this button. |

**⚠ Anti-rollback demo built in:** click **Activate Test Update** a *second* time in a
row (without an intervening rollback). The first click commits application version 2
in `VersionManager`; the second click's package is still version 2, and
`VersionManager.validate_version()` rejects a **replay of an already-committed
version** — so the second `POST /update/activate` returns `activated: false` in the
API terminal. This is `SWR-C-006`/`SWR-C-007` (anti-rollback / anti-replay) working as
designed, not an error — a good live demonstration of **VT-03/VT-12** behaviour.

**⚠ Rollback before any activation:** clicking **Rollback Update** before ever
clicking **Activate Test Update** writes `None`/`null` into `active_application_image`
(there is no `previous_application_image` to restore yet). If you then run VT-13-style
checks against the live sim you'd see a missing image — for a clean demo, always
**Activate** at least once before you **Rollback**.

### 5.3 Diagnostics & Auth

| Button | Calls | Expected result |
|---|---|---|
| **🔍 Log Integrity** | `GET /diagnostics/integrity` | Walks the SHA-256 hash-chained audit log (`SecurityLogger` / `HashChainedLog`) and logs `Audit log integrity: OK ✓` (INFO) or `FAILED ✗` (CRITICAL) into the Event Log panel. Should always be `OK` unless you have manually corrupted `sim/nvm_store.json`. |
| **📋 Load Events (50)** | `GET /diagnostics/events?limit=50` | Pulls the last 50 DEM events recorded so far by the live sim and renders them into the Event Log panel (Panel 4) — see §6, this is currently the *only* way events appear there. |
| **📜 Audit Log** | `GET /diagnostics/audit-log?last_n=30` | Fetches up to 30 hash-chained journal entries and logs a one-line summary (`Audit log: N chain-linked entries returned`). Full entries are visible in the raw JSON in the API Terminal, not in the Event Log panel. |
| **🔑 List Trust Anchors** | `GET /auth/keys` | Lists registered HSM key IDs (`oem_root_key`, `oem_signing_key`, `bootloader_key`, `debug_auth_key`) as one INFO log line. |

**Not exposed as buttons (available via curl/API only):** `POST /auth/debug-access`
and `POST /auth/rotate-key` are implemented (`api/routers/auth.py`) and drive the
`debug_access` / `key_rotation` WebSocket message types the JS already listens for,
but no button in this build triggers them. To exercise them manually:
```bash
curl -X POST http://localhost:8000/auth/rotate-key \
  -H "Content-Type: application/json" \
  -d '{"new_key_id":"oem_signing_key_v2","authorization_sig":"<hex-encoded-signature-from-oem_root_key>"}'
```

---

## 6. Panel 3 — Test Scenario Runner

Lists all 22 VTCs (`VT-01`…`VT-22`), loaded once at page load from `GET /test/list`.

| Control | Behaviour |
|---|---|
| **▶ Run All** | Runs every runnable VTC sequentially (`POST /test/{id}/run` for each), skipping VT-18/VT-19, then marks those two `SKIP`. Summary chip at top-right updates live (`N✓ N✗ N⊘ / 22`). |
| **↺ Clear** | Resets all rows to `—` (pending), does not affect the backend. |
| **▶ per row** | Runs a single VTC. Disabled for VT-18 and VT-19 (greyed out row, "skip" styling) — these are hardware/timer-dependent and intentionally excluded from Phase-1 simulation, matching `requirements/traceability_matrix.md` §6. |
| Row colour | Amber = running, green border = `PASS`, red border = `FAIL`, dim/greyed = `SKIP`. |

**⚠ Important — this is not the same test suite as `pytest tests/ -v`.** Each VTC here
runs a small, self-contained assertion script inside `api/routers/test_scenarios.py`
against a **fresh, isolated simulation stack** (own temp NvM file, own HSM keys) — it
is *not* invoking the pytest files under `tests/`, and the VTC **descriptions shown in
this panel are shorter, implementation-focused summaries**, not the formal test
objectives in `requirements/TestCase.txt`. For example, the panel's "VT-01" here is
"Application image signature verification (valid and tampered)", while
`TestCase.txt`'s VT-01 is the broader "Bootloader signature verification test". Both
IDs map to the same requirement area but exercise it differently. **Use this panel for
fast, visual, live confidence-checking during a demo or walkthrough — use
`pytest tests/ -v --tb=short` (see `requirements/traceability_matrix.md`) as the
authoritative, VERIFIED-status test evidence.**

A `PASS` here means the isolated assertions inside that VTC's function all held; a
`FAIL` means an `AssertionError` was raised (hover the status text to see the
assertion message as a tooltip); `ERROR` (styled like fail) means an unexpected
exception occurred.

---

## 7. Panel 4 — Security Event Log

Shows DEM (Diagnostic Event Manager) security events: timestamp, severity
(`INFO`/`WARNING`/`CRITICAL`, colour-coded), message, and event ID.

| Control | Behaviour |
|---|---|
| **📋 Load History** | Same as **Load Events (50)** in Panel 2 — fetches `GET /diagnostics/events?limit=50` and re-renders the whole log from that snapshot. |
| **⊘ Clear** | Clears the panel client-side only; does **not** clear the backend's DEM event store (there is no clear-DEM endpoint exposed, by design — events are meant to be a forensic record). |
| **Events: N** counter | Counts entries rendered client-side since the page loaded (or since last **Clear**), not the true backend total. |

**⚠ Note — this panel is not truly "live-push" despite the "live ● ws" label.** The
WebSocket message handler for `dem_event` (`addDemEvent()`) is fully implemented and
would append a new log line the instant a `dem_event` message arrived — but no backend
route in the current build actually calls `manager.broadcast_dem_event(...)`
(`api/websocket.py` defines it, nothing calls it). In practice this means: **actions
like Start Boot Sequence, Activate Test Update, etc. record events into the backend's
DEM store immediately, but you will not see them appear here until you click Load
History / Load Events (50).** Get in the habit of clicking **Load History** after any
sequence of operations in Panel 2 to see what was actually logged.

---

## 8. Guided validation walkthroughs

These map dashboard actions to the requirements/VTCs they demonstrate. Click
**↺ Reset ECU** and **↺ Clear** (VTC panel) between walkthroughs for a clean baseline.

### 8.1 Golden-path boot (SWR-C-001, SWR-C-002, SWR-C-008)
1. **Reset ECU** → phase shows `POWER_OFF`.
2. **Start Boot Sequence** → phase flow animates ROM_INIT → BOOTLOADER_VERIFY →
   APPLICATION_VERIFY → **NORMAL_OPERATION** (green), Boot Attempts = 1.
3. Click **Load History** → see `BOOT_ROM_INIT`, `BOOTLOADER_FACTORY_VERIFIED`,
   `BOOT_COMPLETE`-style INFO events.

### 8.2 Boot lockout after repeated attempts (SWR-C-012, VT-07)
1. **Reset ECU**.
2. Click **Start Boot Sequence** four times in a row, watching **Boot Attempts**.
   `MAX_BOOT_RETRY_ATTEMPTS = 3`, so on the **4th** click the phase diagram jumps to
   **`LOCKED_OUT`** (amber side node) instead of `NORMAL_OPERATION`, and the API
   terminal response shows `"success": false, "phase_reached": "LOCKED_OUT"`.
3. Only **Reset ECU** clears this.

### 8.3 Anti-rollback / anti-replay on firmware update (SWR-C-006, SWR-C-007, VT-03, VT-12)
1. **Reset ECU**.
2. **Activate Test Update** → API terminal shows `"activated": true`.
3. **Activate Test Update** again immediately → `"activated": false` (replay of an
   already-committed version 2 is rejected).
4. **Rollback Update** → restores the pre-update image; `"rolled_back": true`.

### 8.4 Authenticated recovery flashing (SR-017, VT-05)
1. **Enter Recovery** → phase diagram shows `SAFE_STATE` (red) — see §4.1 note on
   why this is `SAFE_STATE` and not `RECOVERY_MODE` in this build.
2. **Flash Test Image** → `"flashed": true` (OEM-signed test image accepted).
3. **Load History** → look for `RECOVERY_MODE_ENTERED` and `RECOVERY_FLASH_SUCCESS`
   events.

### 8.5 Audit log tamper-evidence (SWR-C-010, VT-15)
1. **Log Integrity** → should log `Audit log integrity: OK ✓` (INFO).
2. This uses the SHA-256 hash-chained `HashChainedLog` — to actually see a `FAILED`
   result you would need to hand-edit `sim/nvm_store.json`'s
   `audit_log_hash_chain` entry while the backend is stopped, then restart and
   re-check. Not recommended on a running demo — use VT-15 in the Test Scenario
   Runner instead, which does this safely inside an isolated sim.

### 8.6 Full VTC regression sweep (all SWR-C, dashboard-level)
1. In Panel 3, click **▶ Run All**.
2. Expect **20 PASS**, **2 SKIP** (VT-18, VT-19 — hardware/timer-only, greyed out),
   **0 FAIL**. Summary chip should read `20✓ 2⊘ / 22`.
3. For the authoritative, requirement-linked pass/fail record used in
   `requirements/traceability_matrix.md`, run `pytest tests/ -v --tb=short` from a
   terminal instead (119 passed / 9 skipped across the full pytest suite, which
   includes additional step-level assertions beyond what each dashboard VTC checks).

---

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Full-screen "⚡ Backend Offline" overlay | `uvicorn` not running, or crashed | Start it: `uvicorn api.main:app --reload --port 8000`, then click **▶ Connect Now**. |
| WS chip stuck on "Connecting…" / all buttons return network errors | Page opened as `file://...SecureBoot.html` instead of via `http://localhost:3000/...` | Must be served via `python -m http.server 3000 --directory docs` (or `launch.bat`) — CORS in `api/main.py` only allows origin `http://localhost:3000`. |
| VTC panel says "Connecting to backend…" forever | `GET /test/list` failed | Confirm backend is reachable at `http://localhost:8000/health`. |
| Event Log panel looks empty after actions | Expected — see §7 note; events aren't pushed live | Click **Load History**. |
| Attestation Hash row never appears | Expected — see §4.3 note; not wired to the live WS payload | Check attestation via VT-10 in the Test Scenario Runner instead. |
| Debug Interface always shows `OPEN`, Lifecycle badge always `DEVELOPMENT` | Expected — see §3 note; no console button changes lifecycle | Use VT-06/VT-09 in the Test Scenario Runner to see PRODUCTION-lifecycle debug-lock behaviour. |
