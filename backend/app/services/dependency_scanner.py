"""Dependency vulnerability scanner with tool-based and fallback detection.

Detects dependency manifest files (requirements.txt, package.json, etc.),
then runs pip-audit or npm audit when available. Falls back to a curated
list of known vulnerable package versions.
"""

import json
import logging
import os
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

# ── Dependency file names to detect ───────────────────────────────────────

DEPENDENCY_FILES: frozenset[str] = frozenset((
    "requirements.txt", "Pipfile", "pyproject.toml",
    "package.json", "package-lock.json",
    "Gemfile", "go.mod", "Cargo.toml",
))

# ── Known vulnerable packages (fallback database) ────────────────────────

# Format: (package_name, vulnerable_below, cve_id, severity, description)
KNOWN_VULNERABLE_PYTHON: tuple[tuple[str, str, str, str, str], ...] = (
    ("requests", "2.31.0", "CVE-2023-32681",
     "MEDIUM", "Unintended leak of Proxy-Authorization header"),
    ("urllib3", "2.0.7", "CVE-2023-45803",
     "MEDIUM", "Request body not stripped on redirect"),
    ("django", "4.2.8", "CVE-2023-46695",
     "HIGH", "Potential DoS in UsernameField"),
    ("flask", "2.3.3", "CVE-2023-30861",
     "HIGH", "Cookie session can be shared across subdomains"),
    ("werkzeug", "3.0.1", "CVE-2023-46136",
     "HIGH", "DoS via multipart form data parsing"),
    ("cryptography", "41.0.6", "CVE-2023-49083",
     "HIGH", "NULL pointer dereference in PKCS12 parsing"),
    ("certifi", "2023.7.22", "CVE-2023-37920",
     "HIGH", "Removal of e-Tugra root certificate"),
    ("pillow", "10.0.1", "CVE-2023-44271",
     "HIGH", "DoS via uncontrolled resource consumption"),
    ("aiohttp", "3.9.0", "CVE-2023-49081",
     "HIGH", "HTTP header injection via version in request"),
    ("jinja2", "3.1.3", "CVE-2024-22195",
     "MEDIUM", "XSS via xmlattr filter"),
    ("sqlalchemy", "2.0.23", "CVE-2024-23897",
     "MEDIUM", "SQL injection in generic column expression"),
    ("tornado", "6.3.3", "CVE-2023-28370",
     "MEDIUM", "Open redirect vulnerability"),
)

KNOWN_VULNERABLE_NODE: tuple[tuple[str, str, str, str, str], ...] = (
    ("lodash", "4.17.21", "CVE-2021-23337",
     "HIGH", "Command injection via template function"),
    ("axios", "1.6.0", "CVE-2023-45857",
     "HIGH", "CSRF token exposure via cookies"),
    ("express", "4.18.2", "CVE-2024-29041",
     "MEDIUM", "Open redirect in malformed URLs"),
    ("jsonwebtoken", "9.0.0", "CVE-2022-23529",
     "CRITICAL", "Arbitrary code execution via secret key"),
    ("minimist", "1.2.8", "CVE-2021-44906",
     "CRITICAL", "Prototype pollution"),
    ("semver", "7.5.2", "CVE-2022-25883",
     "HIGH", "ReDoS via crafted version strings"),
    ("tough-cookie", "4.1.3", "CVE-2023-26136",
     "MEDIUM", "Prototype pollution in cookie parsing"),
    ("word-wrap", "1.2.4", "CVE-2023-26115",
     "MEDIUM", "ReDoS vulnerability"),
    ("xml2js", "0.5.0", "CVE-2023-0842",
     "MEDIUM", "Prototype pollution"),
    ("postcss", "8.4.31", "CVE-2023-44270",
     "MEDIUM", "Line return parsing issue"),
)


def run_dependency_scan(repo_path: str) -> list[dict[str, Any]]:
    """Scan repo for dependency vulnerabilities.

    Detects manifest files, runs appropriate audit tools, and falls back
    to version checking against known CVEs. Never raises.
    """
    try:
        manifests = _detect_manifests(repo_path)
        if not manifests:
            logger.info("No dependency manifests found")
            return []

        findings: list[dict[str, Any]] = []

        if "requirements.txt" in manifests:
            findings.extend(_scan_python_deps(manifests["requirements.txt"]))
        if "pyproject.toml" in manifests:
            findings.extend(_scan_pyproject(manifests["pyproject.toml"]))
        if "package.json" in manifests:
            findings.extend(_scan_node_deps(manifests["package.json"]))

        logger.info("Dependency scanner found %d vulnerabilities", len(findings))
        return findings

    except Exception:
        logger.exception("Dependency scanner failed")
        return []


def _detect_manifests(repo_path: str) -> dict[str, str]:
    """Walk the repo and find dependency manifest files.

    Returns a dict mapping manifest filename to its full path.
    Only returns the first instance of each manifest type found.
    """
    found: dict[str, str] = {}

    for root, dirs, files in os.walk(repo_path):
        # Skip non-essential directories
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}
        ]

        for fname in files:
            if fname in DEPENDENCY_FILES and fname not in found:
                found[fname] = os.path.join(root, fname)

    return found


# ── Python dependency scanning ────────────────────────────────────────────

def _scan_python_deps(req_path: str) -> list[dict[str, Any]]:
    """Scan Python requirements.txt — try pip-audit, fall back to version check."""
    try:
        return _run_pip_audit(req_path)
    except FileNotFoundError:
        logger.info("pip-audit not installed, using fallback version checker")
    except Exception:
        logger.warning("pip-audit failed, using fallback version checker")

    return _check_python_versions(req_path)


def _run_pip_audit(req_path: str) -> list[dict[str, Any]]:
    """Execute pip-audit and parse JSON output."""
    result = subprocess.run(
        ["pip-audit", "--format", "json", "-r", req_path],
        capture_output=True,
        text=True,
        timeout=120,
    )

    findings: list[dict[str, Any]] = []
    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return []

    for vuln in data.get("dependencies", []):
        for v in vuln.get("vulns", []):
            findings.append(_make_dep_finding(
                file_path=req_path,
                package_name=vuln.get("name", "unknown"),
                installed_version=vuln.get("version", "unknown"),
                cve_id=v.get("id", ""),
                severity=_pip_audit_severity(v),
                description=v.get("description", "Known vulnerability"),
                fix_version=v.get("fix_versions", [None])[0] if v.get("fix_versions") else None,
                tool_name="pip-audit",
            ))

    return findings


def _pip_audit_severity(vuln: dict) -> str:
    """Map pip-audit vulnerability info to severity level."""
    vid = vuln.get("id", "")
    # pip-audit doesn't always include severity; default to HIGH for CVEs
    if vid.startswith("CVE"):
        return "HIGH"
    if vid.startswith("PYSEC"):
        return "MEDIUM"
    return "MEDIUM"


def _check_python_versions(req_path: str) -> list[dict[str, Any]]:
    """Fall back to checking pinned versions against known vulnerable list."""
    try:
        content = open(req_path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return []

    parsed = _parse_requirements(content)
    return _match_vulnerabilities(parsed, KNOWN_VULNERABLE_PYTHON, req_path)


def _parse_requirements(content: str) -> dict[str, str]:
    """Parse requirements.txt into {package_name: version} dict."""
    packages: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        # Match: package==version or package>=version
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*[=<>!~]=?\s*([0-9][0-9a-zA-Z.*]*)", line)
        if match:
            packages[match.group(1).lower()] = match.group(2)
    return packages


# ── pyproject.toml scanning ───────────────────────────────────────────────

def _scan_pyproject(pyproject_path: str) -> list[dict[str, Any]]:
    """Scan pyproject.toml dependencies against known vulnerable list."""
    try:
        content = open(pyproject_path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return []

    parsed = _parse_pyproject_deps(content)
    return _match_vulnerabilities(parsed, KNOWN_VULNERABLE_PYTHON, pyproject_path)


def _parse_pyproject_deps(content: str) -> dict[str, str]:
    """Extract dependency names and versions from pyproject.toml."""
    packages: dict[str, str] = {}

    # Match lines like: "requests>=2.28.0" or 'django~=4.2'
    for match in re.finditer(
        r'["\']([a-zA-Z0-9_.-]+)\s*[><=~!]+\s*([0-9][0-9a-zA-Z.*]*)', content
    ):
        packages[match.group(1).lower()] = match.group(2)

    return packages


# ── Node dependency scanning ──────────────────────────────────────────────

def _scan_node_deps(package_json_path: str) -> list[dict[str, Any]]:
    """Scan Node.js deps — try npm audit, fall back to version check."""
    pkg_dir = os.path.dirname(package_json_path)

    try:
        return _run_npm_audit(pkg_dir, package_json_path)
    except FileNotFoundError:
        logger.info("npm not installed, using fallback version checker")
    except Exception:
        logger.warning("npm audit failed, using fallback version checker")

    return _check_node_versions(package_json_path)


def _run_npm_audit(pkg_dir: str, package_json_path: str) -> list[dict[str, Any]]:
    """Execute npm audit and parse JSON output."""
    result = subprocess.run(
        ["npm", "audit", "--json"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=pkg_dir,
    )

    findings: list[dict[str, Any]] = []
    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return []

    npm_sev_map = {
        "critical": "CRITICAL", "high": "HIGH",
        "moderate": "MEDIUM", "low": "LOW", "info": "INFO",
    }

    vulnerabilities = data.get("vulnerabilities", {})
    for pkg_name, vuln_info in vulnerabilities.items():
        severity = npm_sev_map.get(vuln_info.get("severity", ""), "MEDIUM")
        via_list = vuln_info.get("via", [])
        description = _extract_npm_description(via_list)
        cve_id = _extract_npm_cve(via_list)

        findings.append(_make_dep_finding(
            file_path=package_json_path,
            package_name=pkg_name,
            installed_version=vuln_info.get("range", "unknown"),
            cve_id=cve_id,
            severity=severity,
            description=description,
            fix_version=vuln_info.get("fixAvailable", {}).get("version") if isinstance(vuln_info.get("fixAvailable"), dict) else None,
            tool_name="npm_audit",
        ))

    return findings


def _extract_npm_description(via_list: list) -> str:
    """Extract human-readable description from npm audit 'via' field."""
    for item in via_list:
        if isinstance(item, dict) and item.get("title"):
            return str(item["title"])
    return "Known vulnerability in dependency"


def _extract_npm_cve(via_list: list) -> str | None:
    """Extract CVE ID from npm audit 'via' field."""
    for item in via_list:
        if isinstance(item, dict):
            cves = item.get("cves", [])
            if cves:
                return str(cves[0])
            url = item.get("url", "")
            cve_match = re.search(r"(CVE-\d{4}-\d+)", url)
            if cve_match:
                return cve_match.group(1)
    return None


def _check_node_versions(package_json_path: str) -> list[dict[str, Any]]:
    """Fall back to checking package.json versions against known CVE list."""
    try:
        content = open(package_json_path, encoding="utf-8", errors="ignore").read()
        data = json.loads(content)
    except (OSError, json.JSONDecodeError):
        return []

    parsed = _parse_package_json_deps(data)
    return _match_vulnerabilities(parsed, KNOWN_VULNERABLE_NODE, package_json_path)


def _parse_package_json_deps(data: dict) -> dict[str, str]:
    """Extract dependency versions from parsed package.json."""
    packages: dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, version_spec in deps.items():
            # Strip ^, ~, >= prefixes to get the base version
            clean = re.sub(r"^[\^~>=<!\s]+", "", str(version_spec))
            if clean and clean[0].isdigit():
                packages[name.lower()] = clean
    return packages


# ── Shared helpers ────────────────────────────────────────────────────────

def _match_vulnerabilities(
    parsed_deps: dict[str, str],
    known_vulns: tuple[tuple[str, str, str, str, str], ...],
    file_path: str,
) -> list[dict[str, Any]]:
    """Match parsed dependency versions against known vulnerable versions."""
    findings: list[dict[str, Any]] = []

    for pkg_name, vuln_below, cve_id, severity, description in known_vulns:
        installed = parsed_deps.get(pkg_name)
        if installed is None:
            continue
        if _version_is_below(installed, vuln_below):
            findings.append(_make_dep_finding(
                file_path=file_path,
                package_name=pkg_name,
                installed_version=installed,
                cve_id=cve_id,
                severity=severity,
                description=description,
                fix_version=vuln_below,
                tool_name="version_checker",
            ))

    return findings


def _version_is_below(installed: str, threshold: str) -> bool:
    """Compare two dotted version strings. Returns True if installed < threshold."""
    try:
        inst_parts = [int(x) for x in re.split(r"[.\-a-zA-Z]", installed) if x.isdigit()]
        thresh_parts = [int(x) for x in re.split(r"[.\-a-zA-Z]", threshold) if x.isdigit()]

        # Pad shorter list with zeros for comparison
        max_len = max(len(inst_parts), len(thresh_parts))
        inst_padded = inst_parts + [0] * (max_len - len(inst_parts))
        thresh_padded = thresh_parts + [0] * (max_len - len(thresh_parts))

        return inst_padded < thresh_padded
    except (ValueError, TypeError):
        return False


def _make_dep_finding(
    file_path: str,
    package_name: str,
    installed_version: str,
    cve_id: str | None,
    severity: str,
    description: str,
    fix_version: str | None,
    tool_name: str,
) -> dict[str, Any]:
    """Create a standardized finding dict for a vulnerable dependency."""
    fix_msg = f"Upgrade {package_name} to >= {fix_version}." if fix_version else f"Upgrade {package_name} to the latest version."

    return {
        "scan_id": None,
        "agent_name": "dependency_audit",
        "tool_name": tool_name,
        "category": "vulnerable_dependency",
        "severity": severity,
        "confidence": "high",
        "title": f"Vulnerable dependency: {package_name} {installed_version}",
        "description": f"{description} ({cve_id})" if cve_id else description,
        "file_path": file_path,
        "line_start": None,
        "line_end": None,
        "code_snippet": None,
        "cwe_id": None,
        "cve_id": cve_id,
        "remediation": fix_msg,
    }
