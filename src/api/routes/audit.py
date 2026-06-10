"""Audit log route handlers."""

from __future__ import annotations

from fastapi import APIRouter

from src.fips import FIPSMode

router = APIRouter()


@router.get("/audit/log")
async def get_audit_log(
    last: int = 50,
    operation: str | None = None,
) -> dict:
    """Retrieve recent audit log entries.

    Note: In production, this would query a persistent store (CloudWatch, Splunk, etc.).
    This demo endpoint returns a placeholder.
    """
    return {
        "message": "Audit logs are emitted to structured log output (stdout/CloudWatch/Splunk)",
        "note": "Configure LOG_DESTINATION environment variable for log shipping",
        "last_requested": last,
        "operation_filter": operation,
    }


@router.get("/compliance/fips")
async def fips_status() -> dict:
    """Get FIPS 140-3 compliance status and report."""
    return FIPSMode.get_compliance_report()
