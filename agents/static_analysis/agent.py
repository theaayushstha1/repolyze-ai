"""StaticAnalysisAgent — wraps semgrep and bandit scanning tools.

Takes file paths grouped by language and returns pattern-based vulnerability
findings using the Google ADK LlmAgent pattern.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent

from agents.static_analysis.tools import bandit_scan, semgrep_scan


MODEL = "gemini-2.5-flash"

INSTRUCTION = """You are a static analysis security agent. Your job is to:

1. Run semgrep_scan on the repository for the detected languages.
2. If Python files are present, also run bandit_scan.
3. Parse all results and return a structured list of findings.

Each finding must include:
- file_path: the affected file
- line_number: the line where the issue occurs
- severity: critical / high / medium / low / info
- rule_id: the rule that triggered
- message: human-readable description
- tool: which tool found it (semgrep or bandit)

Return findings sorted by severity (critical first).
Do NOT fabricate findings — only report what the tools return.
"""

static_analysis_agent = LlmAgent(
    name="StaticAnalysisAgent",
    model=MODEL,
    instruction=INSTRUCTION,
    tools=[semgrep_scan, bandit_scan],
)
