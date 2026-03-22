"""High-level scan orchestration service.

This module coordinates the full scan lifecycle:
clone -> detect -> analyse -> persist findings -> generate report.

Currently a placeholder; the concrete analysis pipeline will be
implemented in subsequent iterations.
"""

import logging
from uuid import UUID

from app.db import scan_repo
from app.models.scan import ScanStatus
from app.services.github_service import (
    cleanup_repo,
    clone_repo,
    detect_agents,
    detect_languages,
    detect_mcp_servers,
)

logger = logging.getLogger(__name__)


def run_scan_pipeline(scan_id: UUID) -> None:
    """Execute the full scan pipeline for a given scan record.

    Steps:
        1. Mark scan as cloning and shallow-clone the repo.
        2. Detect languages, agent frameworks, and MCP servers.
        3. Mark scan as analyzing (placeholder).
        4. Mark scan as completed.

    On failure the scan is moved to the FAILED status with an error
    message.
    """
    row = scan_repo.get_scan(scan_id)
    if row is None:
        logger.error("Scan %s not found, aborting pipeline", scan_id)
        return

    repo_path: str | None = None

    try:
        # --- Clone phase ---
        scan_repo.update_scan_status(scan_id, status=ScanStatus.CLONING)
        scan_repo.update_scan_progress(scan_id, progress=10)

        repo_path = clone_repo(
            row["repo_url"],
            branch=row.get("branch", "main"),
        )
        scan_repo.update_scan_progress(scan_id, progress=25)

        # --- Detection phase ---
        languages = detect_languages(repo_path)
        agents = detect_agents(repo_path)
        mcp_servers = detect_mcp_servers(repo_path)

        scan_repo.update_scan_progress(
            scan_id,
            progress=40,
            languages_detected=languages,
        )

        logger.info(
            "Scan %s: languages=%s agents=%s mcp_files=%d",
            scan_id,
            languages,
            agents,
            len(mcp_servers),
        )

        # --- Analysis phase (placeholder) ---
        scan_repo.update_scan_status(scan_id, status=ScanStatus.ANALYZING)
        scan_repo.update_scan_progress(scan_id, progress=60)

        # TODO: Run semgrep, AI agents, and other analysis tools here.

        # --- Completion ---
        scan_repo.update_scan_status(scan_id, status=ScanStatus.COMPLETED)
        scan_repo.update_scan_progress(scan_id, progress=100)

    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        scan_repo.update_scan_status(
            scan_id,
            status=ScanStatus.FAILED,
            error_message=str(exc),
        )
    finally:
        if repo_path is not None:
            cleanup_repo(repo_path)
