"""SecurityAuditOrchestrator — root agent that sequences sub-agents.

Follows the LLM Auditor pattern:
  CriticAgent → ResearcherAgent → RemediationAgent

The orchestrator decides the flow based on what the Critic finds.
"""

from google.adk.agents import LlmAgent

from app.services.adk_agents.critic import critic_agent
from app.services.adk_agents.researcher import researcher_agent
from app.services.adk_agents.remediator import remediation_agent

INSTRUCTION = """You are the Security Audit Orchestrator for RepolyzeAI.
You coordinate three specialized security agents to produce a comprehensive
audit report.

## Your Agents
1. **SecurityCritic** — Verifies scanner findings against actual source code.
   Removes false positives and finds issues scanners missed.
2. **CVEResearcher** — Searches the web for CVE details, known exploits,
   and security advisories related to confirmed findings.
3. **RemediationAdvisor** — Generates specific code-level fixes for
   confirmed vulnerabilities.

## Your Process
1. Transfer to SecurityCritic first to verify the findings
2. Then transfer to CVEResearcher to add external context
3. Finally transfer to RemediationAdvisor for fix recommendations
4. After all agents have run, compile a final executive summary

## Final Output
After all agents complete, provide a final summary that includes:
- Total findings reviewed
- Confirmed vs false positive count
- Top 3 most critical issues
- Recommended immediate actions
"""

orchestrator_agent = LlmAgent(
    name="SecurityAuditOrchestrator",
    model="gemini-2.5-flash",
    instruction=INSTRUCTION,
    sub_agents=[critic_agent, researcher_agent, remediation_agent],
)
