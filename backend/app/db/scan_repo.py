"""Repository layer for scan persistence (Supabase)."""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from app.db.client import get_supabase_client
from app.models.scan import ScanStatus

TABLE = "scans"


def create_scan(
    *,
    repo_url: str,
    repo_name: str,
    branch: str,
    user_id: str | None = None,
) -> dict[str, Any]:
    """Insert a new scan record and return the created row."""
    client = get_supabase_client()
    payload = {
        "repo_url": repo_url,
        "repo_name": repo_name,
        "branch": branch,
        "status": ScanStatus.QUEUED,
        "progress": 0,
        "user_id": user_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    result = client.table(TABLE).insert(payload).execute()
    return result.data[0]


def get_scan(scan_id: UUID) -> dict[str, Any] | None:
    """Fetch a single scan by its primary key."""
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select("*")
        .eq("id", str(scan_id))
        .maybe_single()
        .execute()
    )
    return result.data


def update_scan_status(
    scan_id: UUID,
    *,
    status: ScanStatus,
    error_message: str | None = None,
) -> dict[str, Any] | None:
    """Transition a scan to a new status."""
    client = get_supabase_client()
    payload: dict[str, Any] = {
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if error_message is not None:
        payload["error_message"] = error_message
    if status == ScanStatus.COMPLETED:
        payload["completed_at"] = datetime.now(timezone.utc).isoformat()

    result = (
        client.table(TABLE)
        .update(payload)
        .eq("id", str(scan_id))
        .execute()
    )
    return result.data[0] if result.data else None


def update_scan_progress(
    scan_id: UUID,
    *,
    progress: int,
    languages_detected: list[str] | None = None,
) -> dict[str, Any] | None:
    """Update the numeric progress and optional metadata."""
    client = get_supabase_client()
    payload: dict[str, Any] = {
        "progress": min(max(progress, 0), 100),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if languages_detected is not None:
        payload["languages_detected"] = languages_detected

    result = (
        client.table(TABLE)
        .update(payload)
        .eq("id", str(scan_id))
        .execute()
    )
    return result.data[0] if result.data else None


def list_user_scans(
    user_id: str,
    *,
    page: int = 1,
    limit: int = 20,
) -> tuple[list[dict[str, Any]], int]:
    """Return paginated scans for a given user.

    Returns a tuple of (rows, total_count).
    """
    client = get_supabase_client()
    offset = (page - 1) * limit

    result = (
        client.table(TABLE)
        .select("*", count="exact")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .range(offset, offset + limit - 1)
        .execute()
    )
    total = result.count if result.count is not None else 0
    return result.data, total
