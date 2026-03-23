"""High-level scan orchestration service.

Coordinates the full scan lifecycle:
clone -> detect -> analyse -> persist findings -> generate report.
Uses demo_store for DB access (3-tier: Supabase -> Postgres -> in-memory).
"""

import logging
from datetime import datetime, timezone
from uuid import UUID

from app.demo_store import get_scan, update_scan, add_findings
from app.services.real_scan_service import run_full_scan

logger = logging.getLogger(__name__)


def run_scan_pipeline(scan_id: str | UUID) -> None:
    """Execute the full scan pipeline for a given scan record.

    Steps:
        1. Mark scan as cloning.
        2. Run the real scan pipeline (clone, detect, analyse).
        3. Persist findings.
        4. Mark scan as completed with results.

    On failure the scan is moved to the FAILED status with an error message.
    """
    sid = str(scan_id)
    row = get_scan(sid)
    if row is None:
        logger.error("Scan %s not found, aborting pipeline", sid)
        return

    try:
        update_scan(sid, status="cloning", progress=10, current_step="Cloning repository...")

        result = run_full_scan(
            repo_url=row["repo_url"],
            branch=row.get("branch", "main"),
        )

        if result.get("status") == "failed":
            update_scan(
                sid,
                status="failed",
                error_message=result.get("error_message", "Unknown error"),
            )
            return

        update_scan(
            sid,
            status="analyzing",
            progress=60,
            current_step="Running security analysis...",
            languages_detected=result.get("languages_detected", []),
            agents_detected=result.get("agents_detected", []),
            mcp_detected=result.get("mcp_detected", False),
        )

        findings = result.get("findings", [])
        for f in findings:
            f["scan_id"] = sid

        if findings:
            try:
                add_findings(sid, findings)
            except Exception:
                logger.warning("Failed to persist findings", exc_info=True)

        update_scan(
            sid,
            status="completed",
            progress=100,
            current_step="Scan complete!",
            total_findings=result.get("total_findings", 0),
            critical_count=result.get("critical_count", 0),
            high_count=result.get("high_count", 0),
            medium_count=result.get("medium_count", 0),
            low_count=result.get("low_count", 0),
            info_count=result.get("info_count", 0),
            agent_safety_grade=result.get("agent_safety_grade"),
            scan_duration_ms=result.get("scan_duration_ms"),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )

        logger.info(
            "Scan %s completed: %d findings, grade=%s",
            sid, len(findings), result.get("agent_safety_grade"),
        )

    except Exception as exc:
        logger.exception("Scan %s failed", sid)
        update_scan(sid, status="failed", error_message=str(exc))
