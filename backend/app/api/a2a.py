"""A2A (Agent-to-Agent) protocol endpoints.

Implements the A2A protocol so each scanner agent is discoverable
and can be invoked independently by external orchestrators.

See: https://google.github.io/A2A/
"""

from fastapi import APIRouter

router = APIRouter(tags=["a2a"])

# ── Agent Cards ────────────────────────────────────────────────────────────
# Each agent exposes /.well-known/agent.json describing its capabilities

AGENTS = {
    "repolyze-orchestrator": {
        "name": "RepolyzeAI Orchestrator",
        "description": "Root orchestrator that coordinates all security scanning agents",
        "url": "http://localhost:8000",
        "version": "0.1.0",
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
        },
        "skills": [
            {
                "id": "full-scan",
                "name": "Full Security Scan",
                "description": "Clone a GitHub repo and run all scanners (code, agent safety, MCP, secrets, dependencies)",
                "inputModes": ["application/json"],
                "outputModes": ["application/json", "application/pdf"],
            }
        ],
    },
    "static-analysis": {
        "name": "Static Analysis Agent",
        "description": "Runs Semgrep and Bandit for code vulnerability detection",
        "url": "http://localhost:8000",
        "version": "0.1.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "skills": [
            {
                "id": "semgrep-scan",
                "name": "Semgrep Scan",
                "description": "Pattern-based static analysis across 30+ languages",
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            }
        ],
    },
    "agent-safety": {
        "name": "Agent Safety Auditor",
        "description": "Detects AI agent frameworks and audits for safety issues including red-team analysis",
        "url": "http://localhost:8000",
        "version": "0.1.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "skills": [
            {
                "id": "agent-detect",
                "name": "Agent Framework Detection",
                "description": "Auto-detect LangChain, CrewAI, Google ADK, OpenAI Agents SDK",
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
            {
                "id": "agent-redteam",
                "name": "Agent Red-Team Analysis",
                "description": "Test agent code against 90+ adversarial probes with OWASP LLM Top 10 mapping",
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            },
        ],
    },
    "mcp-auditor": {
        "name": "MCP Server Auditor",
        "description": "Analyzes Model Context Protocol server implementations for security issues",
        "url": "http://localhost:8000",
        "version": "0.1.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "skills": [
            {
                "id": "mcp-audit",
                "name": "MCP Tool Security Audit",
                "description": "Check MCP tools for shell execution, file access, missing validation",
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            }
        ],
    },
    "secret-detection": {
        "name": "Secret Detection Agent",
        "description": "Scans for leaked API keys, tokens, and credentials",
        "url": "http://localhost:8000",
        "version": "0.1.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "skills": [
            {
                "id": "secret-scan",
                "name": "Secret Scanner",
                "description": "Detect hardcoded AWS keys, OpenAI tokens, GitHub PATs, private keys, and more",
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            }
        ],
    },
    "dependency-audit": {
        "name": "Dependency Audit Agent",
        "description": "Scans package manifests for known CVEs in dependencies",
        "url": "http://localhost:8000",
        "version": "0.1.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "skills": [
            {
                "id": "dep-scan",
                "name": "Dependency CVE Scanner",
                "description": "Check requirements.txt, package.json, Cargo.toml for vulnerable versions",
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            }
        ],
    },
}


@router.get("/.well-known/agent.json")
async def agent_card():
    """Return the root orchestrator agent card (A2A discovery)."""
    return AGENTS["repolyze-orchestrator"]


@router.get("/api/a2a/agents")
async def list_agents():
    """List all available A2A agents."""
    return {"agents": list(AGENTS.values())}


@router.get("/api/a2a/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get a specific agent's card."""
    agent = AGENTS.get(agent_id)
    if agent is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return agent
