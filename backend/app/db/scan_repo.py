"""Repository layer for scan persistence (Supabase)."""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from app.db.client import get_supabase_client

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
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "repo_url": repo_url,
        "repo_name": repo_name,
        "branch": branch,
        "status": "queued",
        "progress": 0,
        "current_step": "Queued for analysis",
        "user_id": user_id,
        "mcp_detected": False,
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
        "started_at": now,
        "created_at": now,
    }
    result = client.table(TABLE).insert(payload).execute()
    return _normalize(result.data[0])


def get_scan(scan_id: str | UUID) -> dict[str, Any] | None:
    """Fetch a single scan by its primary key."""
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select("*")
        .eq("id", str(scan_id))
        .maybe_single()
        .execute()
    )
    if result.data is None:
        return None
    return _normalize(result.data)


def update_scan(scan_id: str | UUID, **kwargs: Any) -> dict[str, Any] | None:
    """Update arbitrary scan fields."""
    if not kwargs:
        return get_scan(scan_id)

    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .update(kwargs)
        .eq("id", str(scan_id))
        .execute()
    )
    if not result.data:
        return None
    return _normalize(result.data[0])


def list_all_scans(*, limit: int = 100) -> list[dict[str, Any]]:
    """List all scans ordered by creation date."""
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return [_normalize(row) for row in result.data]


def list_user_scans(
    user_id: str,
    *,
    page: int = 1,
    limit: int = 20,
) -> tuple[list[dict[str, Any]], int]:
    """Return paginated scans for a given user."""
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
    return [_normalize(row) for row in result.data], total


def _normalize(row: dict[str, Any]) -> dict[str, Any]:
    """Ensure consistent defaults for optional fields."""
    row.setdefault("mcp_detected", False)
    row.setdefault("total_findings", 0)
    row.setdefault("critical_count", 0)
    row.setdefault("high_count", 0)
    row.setdefault("medium_count", 0)
    row.setdefault("low_count", 0)
    row.setdefault("info_count", 0)
    row.setdefault("agent_safety_grade", None)
    row.setdefault("scan_duration_ms", None)
    row.setdefault("error_message", None)
    row.setdefault("user_id", None)
    row.setdefault("commit_sha", None)
    row.setdefault("current_step", None)
    return row
