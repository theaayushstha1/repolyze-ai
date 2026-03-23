"""Repository layer for AI agent safety findings (Supabase)."""

from typing import Any
from uuid import UUID

from app.db.client import get_supabase_client

TABLE = "agent_findings"


def create_agent_findings(
    scan_id: str | UUID, findings: list[dict[str, Any]]
) -> int:
    """Batch-insert agent safety findings. Returns count inserted."""
    if not findings:
        return 0

    client = get_supabase_client()
    for f in findings:
        f["scan_id"] = str(scan_id)

    result = client.table(TABLE).insert(findings).execute()
    return len(result.data)


def get_agent_findings(scan_id: str | UUID) -> list[dict[str, Any]]:
    """Get all agent safety findings for a scan."""
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select("*")
        .eq("scan_id", str(scan_id))
        .order("severity", desc=False)
        .execute()
    )
    return result.data


def get_agent_findings_filtered(
    scan_id: str | UUID,
    *,
    test_type: str | None = None,
    severity: str | None = None,
    page: int = 1,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Return filtered, paginated agent findings."""
    client = get_supabase_client()
    offset = (page - 1) * limit

    query = (
        client.table(TABLE)
        .select("*", count="exact")
        .eq("scan_id", str(scan_id))
    )

    if test_type is not None:
        query = query.eq("test_type", test_type)
    if severity is not None:
        query = query.eq("severity", severity.upper())

    result = (
        query
        .order("severity", desc=False)
        .range(offset, offset + limit - 1)
        .execute()
    )
    total = result.count if result.count is not None else 0
    return result.data, total
