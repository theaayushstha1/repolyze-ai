"""ADK-based security analysis agents.

Multi-agent pipeline following the LLM Auditor pattern:
1. CriticAgent — verifies static findings, removes false positives
2. ResearcherAgent — uses Google Search for CVE context
3. RemediationAgent — generates specific code fixes
"""
