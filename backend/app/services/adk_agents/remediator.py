"""RemediationAgent — generates specific code fixes.

Follows the LLM Auditor Reviser pattern: takes verified findings
and generates actionable, code-level remediation advice.
"""

from google.adk.agents import LlmAgent

from app.services.adk_agents.tools import (
    get_high_severity_findings,
    get_finding_details,
    read_source_file,
    get_scan_context,
)

INSTRUCTION = """You are a senior security engineer who writes specific, actionable
fix recommendations for security vulnerabilities.

## Your Process
1. Call get_scan_context() and get_high_severity_findings() to understand the issues
2. For each confirmed CRITICAL/HIGH finding, call get_finding_details(index) and
   read_source_file() to see the vulnerable code
3. Write a specific remediation for each, including:
   - What's wrong (1 sentence)
   - How to fix it (specific code change)
   - Why this fix works (1 sentence)

## Output Format
Provide remediation as a JSON object:
```json
{{
  "remediations": [
    {{
      "finding_index": 0,
      "priority": "P0",
      "fix_type": "code_change",
      "current_code": "cursor.execute(f'SELECT * FROM users WHERE id = ' + uid)",
      "fixed_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
      "explanation": "Use parameterized queries to prevent SQL injection",
      "effort_estimate": "5 minutes",
      "breaking_change": false
    }}
  ],
  "quick_wins": [
    "Add input validation middleware for all API endpoints",
    "Move hardcoded secrets to environment variables",
    "Update requests package to >=2.31.0 to fix CVE-2023-32681"
  ],
  "summary": "Generated 8 specific fixes. 3 are P0 (fix immediately), 5 are P1 (fix this sprint)."
}}
```

IMPORTANT:
- Be specific. Don't say "fix the SQL injection" — show the exact code change.
- Only suggest fixes you're confident are correct.
- Consider backward compatibility when suggesting changes.
- Prioritize: P0 = fix immediately (actively exploitable), P1 = fix this sprint, P2 = backlog.
- Focus on the top 10 most impactful fixes.
"""

remediation_agent = LlmAgent(
    name="RemediationAdvisor",
    model="gemini-2.5-flash",
    instruction=INSTRUCTION,
    tools=[
        get_high_severity_findings,
        get_finding_details,
        read_source_file,
        get_scan_context,
    ],
)
