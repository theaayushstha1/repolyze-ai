"""Storage layer with 3-tier fallback: Supabase -> PostgreSQL -> in-memory.

Supabase is used when SUPABASE_URL + key are configured (production).
PostgreSQL is used when Docker Compose DB is running (local dev).
In-memory dicts are the last resort (zero-deps demo mode).
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Tier 1: Try Supabase ────────────────────────────────────────────────
_use_supabase = False
try:
    from app.db.client import is_supabase_available

    if is_supabase_available():
        from app.db.scan_repo import (
            create_scan as sb_create_scan,
            get_scan as sb_get_scan,
            update_scan as sb_update_scan,
            list_all_scans as sb_list_all_scans,
        )
        from app.db.finding_repo import (
            create_findings as sb_create_findings,
            get_findings as sb_get_findings,
        )
        _use_supabase = True
        logger.info("Using Supabase for persistence")
except Exception as exc:
    logger.debug("Supabase not available: %s", exc)

# ── Tier 2: Try local PostgreSQL ────────────────────────────────────────
_use_postgres = False
if not _use_supabase:
    try:
        from app.db.postgres import (
            create_scan as pg_create_scan,
            get_scan as pg_get_scan,
            update_scan as pg_update_scan,
            list_all_scans as pg_list_all_scans,
            create_findings as pg_create_findings,
            get_findings as pg_get_findings,
        )
        import psycopg2
        conn = psycopg2.connect(
            "postgresql://repolyze:repolyze_dev@localhost:5432/repolyze_ai"
        )
        conn.close()
        _use_postgres = True
        logger.info("Using PostgreSQL for persistence")
    except Exception:
        logger.info("PostgreSQL not available, using in-memory storage")

# ── Tier 3: In-memory fallback ──────────────────────────────────────────

_scans: dict[str, dict[str, Any]] = {}
_findings: dict[str, list[dict[str, Any]]] = {}


def _mem_create_scan(repo_url: str, repo_name: str, branch: str) -> dict[str, Any]:
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    scan = {
        "id": scan_id, "user_id": None, "repo_url": repo_url,
        "repo_name": repo_name, "branch": branch, "commit_sha": None,
        "status": "queued", "progress": 0, "current_step": "Queued for analysis",
        "languages_detected": None, "agents_detected": None, "mcp_detected": False,
        "total_findings": 0, "critical_count": 0, "high_count": 0,
        "medium_count": 0, "low_count": 0, "info_count": 0,
        "agent_safety_grade": None, "scan_duration_ms": None,
        "error_message": None, "started_at": now, "completed_at": None,
        "created_at": now,
    }
    _scans[scan_id] = scan
    _findings[scan_id] = []
    return scan


def get_storage_tier() -> str:
    """Return which storage tier is active."""
    if _use_supabase:
        return "supabase"
    if _use_postgres:
        return "postgres"
    return "memory"


# ── Public API ──────────────────────────────────────────────────────────

def create_scan(repo_url: str, repo_name: str, branch: str = "main") -> dict[str, Any]:
    if _use_supabase:
        return sb_create_scan(repo_url=repo_url, repo_name=repo_name, branch=branch)
    if _use_postgres:
        return pg_create_scan(repo_url=repo_url, repo_name=repo_name, branch=branch)
    return _mem_create_scan(repo_url, repo_name, branch)


def get_scan(scan_id: str | uuid.UUID) -> dict[str, Any] | None:
    if _use_supabase:
        return sb_get_scan(str(scan_id))
    if _use_postgres:
        return pg_get_scan(str(scan_id))
    return _scans.get(str(scan_id))


def update_scan(scan_id: str, **kwargs: Any) -> dict[str, Any] | None:
    if _use_supabase:
        return sb_update_scan(str(scan_id), **kwargs)
    if _use_postgres:
        return pg_update_scan(str(scan_id), **kwargs)
    scan = _scans.get(str(scan_id))
    if scan is None:
        return None
    scan.update(kwargs)
    return scan


def add_findings(scan_id: str, findings: list[dict[str, Any]]) -> None:
    if _use_supabase:
        sb_create_findings(str(scan_id), findings)
        return
    if _use_postgres:
        pg_create_findings(str(scan_id), findings)
        return
    if str(scan_id) not in _findings:
        _findings[str(scan_id)] = []
    _findings[str(scan_id)].extend(findings)


def get_findings(scan_id: str | uuid.UUID) -> list[dict[str, Any]]:
    if _use_supabase:
        return sb_get_findings(str(scan_id))
    if _use_postgres:
        return pg_get_findings(str(scan_id))
    return _findings.get(str(scan_id), [])


def get_all_scans() -> list[dict[str, Any]]:
    if _use_supabase:
        return sb_list_all_scans()
    if _use_postgres:
        return pg_list_all_scans()
    return sorted(_scans.values(), key=lambda s: s.get("created_at", ""), reverse=True)
