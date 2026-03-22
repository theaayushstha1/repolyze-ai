"""MCP Server Auditor agent — analyzes MCP tool definitions for security.

Inspects Model Context Protocol server implementations for unsafe tool
patterns, missing input validation, excessive permissions, and other
security risks.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent

from agents.mcp_auditor.analyzer import analyze_mcp_tools


MODEL = "gemini-2.5-flash"

INSTRUCTION = """You are an MCP (Model Context Protocol) server security auditor.
Your job is to:

1. Use analyze_mcp_tools to inspect MCP server implementations in the repository.
2. Evaluate each tool definition for security risks:
   - Overly broad file system access
   - Shell command execution without sandboxing
   - Missing input validation on tool parameters
   - Excessive permissions (read/write when only read is needed)
   - Lack of rate limiting or request size limits
   - Missing authentication/authorization checks
3. Check the MCP server configuration for:
   - Insecure transport (HTTP instead of HTTPS for remote servers)
   - Missing CORS restrictions
   - Exposed internal endpoints

Each finding must include:
- tool_name: the MCP tool with the issue
- file_path: source file location
- severity: critical / high / medium / low
- category: the type of security issue
- message: human-readable description
- recommendation: how to fix the issue

Do NOT fabricate findings — only report what the analyzer returns.
"""

mcp_auditor_agent = LlmAgent(
    name="MCPAuditorAgent",
    model=MODEL,
    instruction=INSTRUCTION,
    tools=[analyze_mcp_tools],
)
