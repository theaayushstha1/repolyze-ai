"""Direct PostgreSQL client for local development.

Uses psycopg2 to connect to the Docker Compose Postgres instance.
This replaces the Supabase client when running locally.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)

# Register UUID adapter
psycopg2.extras.register_uuid()

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://repolyze:repolyze_dev@localhost:5432/repolyze_ai",
)


def _get_conn():
    """Get a new database connection."""
    return psycopg2.connect(DATABASE_URL)


def _row_to_dict(cursor, row) -> dict[str, Any]:
    """Convert a database row to a dict."""
    if row is None:
        return None
    return {desc[0]: row[i] for i, desc in enumerate(cursor.description)}


# ── Scans ────────────────────────────────────────────────────────────────

def create_scan(
    *,
    repo_url: str,
    repo_name: str,
    branch: str,
    user_id: str | None = None,
) -> dict[str, Any]:
    """Insert a new scan and return the row."""
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO scans (id, repo_url, repo_name, branch, user_id,
                   status, progress, current_step, created_at, started_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING *""",
                (scan_id, repo_url, repo_name, branch, user_id,
                 "queued", 0, "Queued for analysis", now, now),
            )
            row = _row_to_dict(cur, cur.fetchone())
            conn.commit()

    # Normalize types for JSON serialization
    return _normalize_scan(row)


def get_scan(scan_id) -> dict[str, Any] | None:
    """Fetch a scan by ID."""
    # Validate UUID format
    try:
        uuid.UUID(str(scan_id))
    except ValueError:
        return None

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id = %s", (str(scan_id),))
            row = _row_to_dict(cur, cur.fetchone())

    if row is None:
        return None
    return _normalize_scan(row)


def update_scan(scan_id: str, **kwargs) -> dict[str, Any] | None:
    """Update arbitrary scan fields."""
    if not kwargs:
        return get_scan(scan_id)

    # Handle JSON fields
    for key in ("languages_detected", "agents_detected"):
        if key in kwargs and isinstance(kwargs[key], list):
            kwargs[key] = json.dumps(kwargs[key])

    set_clauses = ", ".join(f"{k} = %s" for k in kwargs)
    values = list(kwargs.values()) + [str(scan_id)]

    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE scans SET {set_clauses} WHERE id = %s RETURNING *",
                values,
            )
            row = _row_to_dict(cur, cur.fetchone())
            conn.commit()

    if row is None:
        return None
    return _normalize_scan(row)


def list_all_scans() -> list[dict[str, Any]]:
    """List all scans ordered by creation date."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 100")
            rows = [_row_to_dict(cur, row) for row in cur.fetchall()]

    return [_normalize_scan(r) for r in rows]


# ── Findings ─────────────────────────────────────────────────────────────

def create_findings(scan_id: str, findings: list[dict[str, Any]]) -> int:
    """Batch insert findings. Returns count inserted."""
    if not findings:
        return 0

    with _get_conn() as conn:
        with conn.cursor() as cur:
            for f in findings:
                cur.execute(
                    """INSERT INTO findings
                       (id, scan_id, agent_name, tool_name, category, severity,
                        confidence, title, description, file_path, line_start,
                        line_end, code_snippet, cwe_id, cve_id, remediation)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        f.get("id", str(uuid.uuid4())),
                        str(scan_id),
                        f.get("agent_name"),
                        f.get("tool_name"),
                        f.get("category"),
                        f.get("severity"),
                        f.get("confidence"),
                        f.get("title"),
                        f.get("description"),
                        f.get("file_path"),
                        f.get("line_start"),
                        f.get("line_end"),
                        f.get("code_snippet"),
                        f.get("cwe_id"),
                        f.get("cve_id"),
                        f.get("remediation"),
                    ),
                )
            conn.commit()

    return len(findings)


def get_findings(scan_id: str) -> list[dict[str, Any]]:
    """Get all findings for a scan."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM findings WHERE scan_id = %s ORDER BY severity",
                (str(scan_id),),
            )
            rows = [_row_to_dict(cur, row) for row in cur.fetchall()]

    return rows


# ── Helpers ──────────────────────────────────────────────────────────────

def _normalize_scan(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize scan row for JSON serialization."""
    if row is None:
        return None

    # Convert UUID to string
    if "id" in row and not isinstance(row["id"], str):
        row["id"] = str(row["id"])

    # Convert datetime to ISO string
    for key in ("created_at", "started_at", "completed_at"):
        val = row.get(key)
        if val and hasattr(val, "isoformat"):
            row[key] = val.isoformat()

    # Parse JSON fields
    for key in ("languages_detected", "agents_detected"):
        val = row.get(key)
        if isinstance(val, str):
            try:
                row[key] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                pass

    # Ensure defaults
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

    return row
