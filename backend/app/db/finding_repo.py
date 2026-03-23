"""Repository layer for finding persistence (Supabase)."""

from typing import Any
from uuid import UUID

from app.db.client import get_supabase_client
from app.models.finding import FindingSummary

TABLE = "findings"


def create_findings(scan_id: str | UUID, findings: list[dict[str, Any]]) -> int:
    """Batch-insert findings. Returns count inserted."""
    if not findings:
        return 0

    client = get_supabase_client()
    for f in findings:
        f["scan_id"] = str(scan_id)

    result = client.table(TABLE).insert(findings).execute()
    return len(result.data)


def get_findings(scan_id: str | UUID) -> list[dict[str, Any]]:
    """Get all findings for a scan."""
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select("*")
        .eq("scan_id", str(scan_id))
        .order("severity", desc=False)
        .execute()
    )
    return result.data


def get_findings_filtered(
    scan_id: str | UUID,
    *,
    severity: str | None = None,
    category: str | None = None,
    agent_name: str | None = None,
    page: int = 1,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Return filtered, paginated findings for a scan."""
    client = get_supabase_client()
    offset = (page - 1) * limit

    query = (
        client.table(TABLE)
        .select("*", count="exact")
        .eq("scan_id", str(scan_id))
    )

    if severity is not None:
        query = query.eq("severity", severity.upper())
    if category is not None:
        query = query.eq("category", category)
    if agent_name is not None:
        query = query.eq("agent_name", agent_name)

    result = (
        query
        .order("severity", desc=False)
        .range(offset, offset + limit - 1)
        .execute()
    )
    total = result.count if result.count is not None else 0
    return result.data, total


def get_finding_summary(scan_id: str | UUID) -> FindingSummary:
    """Compute aggregated severity counts for a scan."""
    client = get_supabase_client()
    result = (
        client.table(TABLE)
        .select("severity")
        .eq("scan_id", str(scan_id))
        .execute()
    )

    counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    for row in result.data:
        key = row["severity"].lower()
        if key in counts:
            counts[key] += 1

    return FindingSummary(total=sum(counts.values()), **counts)
