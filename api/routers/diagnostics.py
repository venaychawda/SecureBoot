"""Diagnostics router — DEM events, audit log, chain integrity.

GET /diagnostics/events     — DEM event list (optional ?severity= filter)
GET /diagnostics/audit-log  — hash-chained security journal entries
GET /diagnostics/integrity  — verify audit log chain integrity
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/diagnostics", tags=["diagnostics"])


@router.get("/events")
async def get_events(
    request: Request,
    severity: Optional[str] = Query(None, description="INFO | WARNING | CRITICAL"),
    limit: int = Query(100, ge=1, le=1000),
) -> dict:
    sim = request.app.state.sim
    from sim.dem import Severity

    if severity:
        sev = Severity(severity.upper())
        events = sim.dem.get_events_by_severity(sev)
    else:
        events = sim.dem.get_events()

    events = events[-limit:]
    return {
        "events": [
            {
                "event_id": e.event_id,
                "severity": e.severity.value,
                "description": e.description,
                "swr_ref": e.swr_ref,
                "timestamp": e.timestamp,
                "data": e.data,
            }
            for e in events
        ],
        "count": len(events),
    }


@router.get("/audit-log")
async def get_audit_log(
    request: Request,
    last_n: int = Query(50, ge=1, le=500),
) -> dict:
    sim = request.app.state.sim
    entries = sim.sl.get_audit_log(last_n)
    return {"entries": entries, "count": len(entries)}


@router.get("/integrity")
async def check_integrity(request: Request) -> dict:
    sim = request.app.state.sim
    ok = sim.sl.verify_log_integrity()
    return {"integrity_ok": ok}
