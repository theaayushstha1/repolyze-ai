"""Tool wrappers for dependency auditing — osv-scanner, pip-audit, npm audit.

Each function shells out to the respective CLI tool, captures JSON output,
and returns parsed results as structured dictionaries.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


def osv_scan(repo_path: str) -> list[dict[str, Any]]:
    """Run osv-scanner on the repository lockfiles.

    Args:
        repo_path: Path to the repository to scan.

    Returns:
        List of vulnerability finding dictionaries.
    """
    cmd: list[str] = [
        "osv-scanner",
        "--format", "json",
        "--recursive",
        repo_path,
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=300,
    )

    if result.returncode not in (0, 1):
        return [{"error": f"osv-scanner failed: {result.stderr[:500]}"}]

    return _parse_osv_output(result.stdout)


def _parse_osv_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse osv-scanner JSON output into finding dictionaries."""
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return [{"error": "Failed to parse osv-scanner JSON output"}]

    results: list[dict[str, Any]] = []
    for vuln_result in data.get("results", []):
        source = vuln_result.get("source", {}).get("path", "")
        for package_info in vuln_result.get("packages", []):
            pkg = package_info.get("package", {})
            for vuln in package_info.get("vulnerabilities", []):
                finding = {
                    "package_name": pkg.get("name", ""),
                    "installed_version": pkg.get("version", ""),
                    "vulnerability_id": vuln.get("id", ""),
                    "severity": _extract_osv_severity(vuln),
                    "fixed_version": _extract_fixed_version(vuln),
                    "source_file": source,
                    "tool": "osv-scanner",
                }
                results.append(finding)
    return results


def _extract_osv_severity(vuln: dict[str, Any]) -> str:
    """Extract and normalize severity from an OSV vulnerability entry."""
    for severity in vuln.get("severity", []):
        score_str = severity.get("score", "")
        if score_str:
            try:
                score = float(score_str.split("/")[0])
            except (ValueError, IndexError):
                continue
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
    return "medium"


def _extract_fixed_version(vuln: dict[str, Any]) -> str:
    """Extract the fixed version from an OSV vulnerability entry."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return "unknown"


def pip_audit(repo_path: str) -> list[dict[str, Any]]:
    """Run pip-audit on Python dependencies.

    Args:
        repo_path: Path to the repository to scan.

    Returns:
        List of vulnerability finding dictionaries.
    """
    cmd: list[str] = [
        "pip-audit",
        "--format", "json",
        "--path", repo_path,
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=300,
    )

    if result.returncode not in (0, 1):
        return [{"error": f"pip-audit failed: {result.stderr[:500]}"}]

    return _parse_pip_audit_output(result.stdout)


def _parse_pip_audit_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse pip-audit JSON output into finding dictionaries."""
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return [{"error": "Failed to parse pip-audit JSON output"}]

    results: list[dict[str, Any]] = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            finding = {
                "package_name": dep.get("name", ""),
                "installed_version": dep.get("version", ""),
                "vulnerability_id": vuln.get("id", ""),
                "severity": vuln.get("fix_versions", [""])[0] and "high",
                "fixed_version": (
                    vuln.get("fix_versions", ["unknown"])[0] or "unknown"
                ),
                "tool": "pip-audit",
            }
            results.append(finding)
    return results


def npm_audit(repo_path: str) -> list[dict[str, Any]]:
    """Run npm audit on Node.js dependencies.

    Args:
        repo_path: Path to the repository to scan.

    Returns:
        List of vulnerability finding dictionaries.
    """
    cmd: list[str] = [
        "npm", "audit", "--json", "--prefix", repo_path,
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=300,
    )

    # npm audit exits with non-zero when vulnerabilities are found
    return _parse_npm_audit_output(result.stdout)


def _parse_npm_audit_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse npm audit JSON output into finding dictionaries."""
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return [{"error": "Failed to parse npm audit JSON output"}]

    results: list[dict[str, Any]] = []
    vulnerabilities = data.get("vulnerabilities", {})
    for _pkg_name, vuln_info in vulnerabilities.items():
        finding = {
            "package_name": vuln_info.get("name", ""),
            "installed_version": vuln_info.get("range", ""),
            "vulnerability_id": _extract_npm_advisory_id(vuln_info),
            "severity": vuln_info.get("severity", "medium"),
            "fixed_version": vuln_info.get("fixAvailable", "unknown"),
            "tool": "npm-audit",
        }
        results.append(finding)
    return results


def _extract_npm_advisory_id(vuln_info: dict[str, Any]) -> str:
    """Extract the advisory ID from an npm audit vulnerability entry."""
    via = vuln_info.get("via", [])
    if via and isinstance(via[0], dict):
        return via[0].get("url", "unknown")
    return "unknown"
