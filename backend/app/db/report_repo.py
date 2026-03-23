"""Repository layer for report persistence (Supabase)."""

from typing import Any
from uuid import UUID

from app.db.client import get_supabase_client

TABLE = "reports"


def create_report(
    *,
    scan_id: str | UUID,
    report_type: str = "full",
    pdf_storage_path: str | None = None,
    pdf_size_bytes: int | None = None,
    html_content: str | None = None,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Insert a report record and return the created row."""
    client = get_supabase_client()
    payload = {
        "scan_id": str(scan_id),
        "report_type": report_type,
        "pdf_storage_path": pdf_storage_path,
        "pdf_size_bytes": pdf_size_bytes,
        "html_content": html_content,
        "summary": summary,
    }
    result = client.table(TABLE).insert(payload).execute()
    return result.data[0]


def get_report(report_id: str | UUID) -> dict[str, Any] | None:
    """Fetch a report by ID."""
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select("*")
        .eq("id", str(report_id))
        .maybe_single()
        .execute()
    )
    return result.data


def get_latest_report(scan_id: str | UUID) -> dict[str, Any] | None:
    """Fetch the most recent report for a scan."""
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select("*")
        .eq("scan_id", str(scan_id))
        .order("generated_at", desc=True)
        .limit(1)
        .execute()
    )
    if not result.data:
        return None
    return result.data[0]


def list_reports(scan_id: str | UUID) -> list[dict[str, Any]]:
    """List all reports for a scan."""
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select("*")
        .eq("scan_id", str(scan_id))
        .order("generated_at", desc=True)
        .execute()
    )
    return result.data
