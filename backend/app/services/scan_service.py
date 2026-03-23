"""High-level scan orchestration service.

Coordinates the full scan lifecycle:
clone -> detect -> analyse -> persist findings -> generate report.
Uses real_scan_service for actual analysis.
"""

import logging
from uuid import UUID

from app.db import scan_repo, finding_repo
from app.models.scan import ScanStatus
from app.services.real_scan_service import run_full_scan

logger = logging.getLogger(__name__)


def run_scan_pipeline(scan_id: UUID) -> None:
    """Execute the full scan pipeline for a given scan record.

    Steps:
        1. Mark scan as cloning.
        2. Run the real scan pipeline (clone, detect, analyse).
        3. Persist findings to Supabase.
        4. Mark scan as completed with results.

    On failure the scan is moved to the FAILED status with an error
    message.
    """
    row = scan_repo.get_scan(scan_id)
    if row is None:
        logger.error("Scan %s not found, aborting pipeline", scan_id)
        return

    try:
        # --- Update status ---
        scan_repo.update_scan_status(scan_id, status=ScanStatus.CLONING)
        scan_repo.update_scan_progress(scan_id, progress=10)

        # --- Run the real scan pipeline ---
        result = run_full_scan(
            repo_url=row["repo_url"],
            branch=row.get("branch", "main"),
        )

        if result.get("status") == "failed":
            scan_repo.update_scan_status(
                scan_id,
                status=ScanStatus.FAILED,
                error_message=result.get("error_message", "Unknown error"),
            )
            return

        # --- Update detection results ---
        scan_repo.update_scan_status(scan_id, status=ScanStatus.ANALYZING)
        scan_repo.update_scan_progress(
            scan_id,
            progress=60,
            languages_detected=result.get("languages_detected", []),
        )

        # --- Persist findings ---
        findings = result.get("findings", [])
        for f in findings:
            f["scan_id"] = str(scan_id)

        if findings:
            try:
                finding_repo.create_findings(findings)
            except Exception:
                logger.warning("Failed to persist findings to Supabase", exc_info=True)

        # --- Mark completed ---
        scan_repo.update_scan_status(scan_id, status=ScanStatus.COMPLETED)
        scan_repo.update_scan_progress(
            scan_id,
            progress=100,
            total_findings=result.get("total_findings", 0),
            critical_count=result.get("critical_count", 0),
            high_count=result.get("high_count", 0),
            medium_count=result.get("medium_count", 0),
            low_count=result.get("low_count", 0),
            info_count=result.get("info_count", 0),
            agents_detected=result.get("agents_detected", []),
            mcp_detected=result.get("mcp_detected", False),
            agent_safety_grade=result.get("agent_safety_grade"),
            scan_duration_ms=result.get("scan_duration_ms"),
        )

        logger.info(
            "Scan %s completed: %d findings, grade=%s",
            scan_id, len(findings), result.get("agent_safety_grade"),
        )

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        scan_repo.update_scan_status(
            scan_id,
            status=ScanStatus.FAILED,
            error_message=str(exc),
        )
