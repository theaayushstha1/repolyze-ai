"""In-memory store for demo mode (no Supabase/Redis required)."""

import uuid
from datetime import datetime, timezone
from typing import Any

_scans: dict[str, dict[str, Any]] = {}
_findings: dict[str, list[dict[str, Any]]] = {}


def create_scan(repo_url: str, repo_name: str, branch: str = "main") -> dict[str, Any]:
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    scan = {
        "id": scan_id,
        "user_id": None,
        "repo_url": repo_url,
        "repo_name": repo_name,
        "branch": branch,
        "commit_sha": None,
        "status": "queued",
        "progress": 0,
        "current_step": "Queued for analysis",
        "languages_detected": None,
        "agents_detected": None,
        "mcp_detected": False,
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
        "agent_safety_grade": None,
        "scan_duration_ms": None,
        "error_message": None,
        "started_at": now,
        "completed_at": None,
        "created_at": now,
    }
    _scans[scan_id] = scan
    _findings[scan_id] = []
    return scan


def get_scan(scan_id: str | uuid.UUID) -> dict[str, Any] | None:
    return _scans.get(str(scan_id))


def update_scan(scan_id: str, **kwargs: Any) -> dict[str, Any] | None:
    scan = _scans.get(str(scan_id))
    if scan is None:
        return None
    scan.update(kwargs)
    return scan


def add_findings(scan_id: str, findings: list[dict[str, Any]]) -> None:
    if str(scan_id) not in _findings:
        _findings[str(scan_id)] = []
    _findings[str(scan_id)].extend(findings)


def get_findings(scan_id: str | uuid.UUID) -> list[dict[str, Any]]:
    return _findings.get(str(scan_id), [])


def get_all_scans() -> list[dict[str, Any]]:
    """Return all scans sorted by created_at descending."""
    return sorted(_scans.values(), key=lambda s: s.get("created_at", ""), reverse=True)
