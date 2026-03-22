"""DependencyAuditAgent — scans project dependencies for known vulnerabilities.

Uses OSV-Scanner, pip-audit, and npm-audit to identify vulnerable packages
across Python and JavaScript/TypeScript ecosystems.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent

from agents.dependency_audit.tools import npm_audit, osv_scan, pip_audit


MODEL = "gemini-2.5-flash"

INSTRUCTION = """You are a dependency audit security agent. Your job is to:

1. Run osv_scan on the repository to check all lockfiles against the OSV database.
2. If Python dependency files exist (requirements.txt, pyproject.toml, Pipfile.lock),
   also run pip_audit.
3. If Node.js dependency files exist (package-lock.json, yarn.lock),
   also run npm_audit.
4. Merge and deduplicate findings across tools.

Each finding must include:
- package_name: the affected package
- installed_version: the version currently used
- vulnerability_id: CVE or GHSA identifier
- severity: critical / high / medium / low
- fixed_version: the version that fixes the issue (if known)
- tool: which tool found it

Return findings sorted by severity (critical first).
Do NOT fabricate findings — only report what the tools return.
"""

dependency_audit_agent = LlmAgent(
    name="DependencyAuditAgent",
    model=MODEL,
    instruction=INSTRUCTION,
    tools=[osv_scan, pip_audit, npm_audit],
)
