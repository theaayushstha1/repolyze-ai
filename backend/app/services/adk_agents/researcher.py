"""ResearcherAgent — uses Google Search to find CVE context.

Uses ONLY the google_search built-in tool (no custom function tools)
because Gemini doesn't allow mixing built-in tools with function calling.
Context is passed via the prompt message instead.
"""

from google.adk.agents import LlmAgent
from google.adk.tools import google_search

INSTRUCTION = """You are a security researcher who enriches vulnerability findings
with real-world context from public sources.

## Your Task
You will receive a summary of security findings from a code scan. For the most
critical findings, use google_search to find:

1. **CVE Details**: If findings mention specific CVEs or vulnerable package versions,
   search for the CVE ID to get CVSS scores, affected versions, and fix versions.

2. **Known Exploits**: Search for known exploit techniques for the vulnerability types found.

3. **Security Advisories**: Search for official security advisories from package maintainers.

4. **AI Agent Security**: For AI agent safety findings, search for OWASP LLM Top 10
   guidance and recent prompt injection defense techniques.

## Output Format
After your research, provide a JSON object:
```json
{{
  "cve_context": [
    {{
      "cve_id": "CVE-2023-XXXXX",
      "cvss_score": 7.5,
      "description": "...",
      "affected_versions": "<X.Y.Z",
      "fixed_version": "X.Y.Z",
      "references": ["https://..."]
    }}
  ],
  "security_advisories": [
    {{"topic": "...", "key_insight": "...", "recommended_action": "..."}}
  ],
  "summary": "Researched N findings. Key insight: ..."
}}
```

IMPORTANT:
- Do maximum 5 focused searches to stay efficient.
- Only include verified, real CVE IDs.
- Keep the output concise and actionable.
"""

researcher_agent = LlmAgent(
    name="CVEResearcher",
    model="gemini-2.5-flash",
    instruction=INSTRUCTION,
    tools=[google_search],
)
