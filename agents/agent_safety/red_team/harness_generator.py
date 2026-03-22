"""Auto-generate test harnesses for various agent frameworks.

Produces runnable Python scripts that instantiate the agent under test
and expose a callable interface for the red team orchestrator to probe.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HarnessOutput:
    """Immutable test harness output."""

    framework: str
    script: str
    filename: str


def generate_langchain_harness(agent_files: list[str]) -> HarnessOutput:
    """Generate a LangChain/LangGraph agent test harness.

    Args:
        agent_files: List of file paths containing agent definitions.

    Returns:
        HarnessOutput with the executable test script.
    """
    imports = "\n".join(f'# Agent file: {f}' for f in agent_files)
    script = f'''"""Auto-generated LangChain agent test harness."""

import asyncio
import sys
sys.path.insert(0, ".")

{imports}

from langchain_core.messages import HumanMessage


async def create_agent():
    """Instantiate the LangChain agent from discovered files."""
    # TODO: Auto-detect and import the agent class from agent_files
    raise NotImplementedError(
        "Customize this harness with the actual agent import."
    )


async def invoke_agent(prompt: str) -> str:
    """Send a prompt to the agent and return the response."""
    agent = await create_agent()
    result = await agent.ainvoke({{"messages": [HumanMessage(content=prompt)]}})
    messages = result.get("messages", [])
    if messages:
        return messages[-1].content
    return str(result)


async def main():
    """Run the harness with a test prompt."""
    response = await invoke_agent("Hello, what can you do?")
    print(f"Response: {{response}}")


if __name__ == "__main__":
    asyncio.run(main())
'''
    return HarnessOutput(
        framework="langchain",
        script=script,
        filename="harness_langchain.py",
    )


def generate_crewai_harness(agent_files: list[str]) -> HarnessOutput:
    """Generate a CrewAI agent test harness.

    Args:
        agent_files: List of file paths containing agent definitions.

    Returns:
        HarnessOutput with the executable test script.
    """
    imports = "\n".join(f'# Agent file: {f}' for f in agent_files)
    script = f'''"""Auto-generated CrewAI agent test harness."""

import asyncio
import sys
sys.path.insert(0, ".")

{imports}


async def create_agent():
    """Instantiate the CrewAI agent from discovered files."""
    # TODO: Auto-detect and import the crew/agent class from agent_files
    raise NotImplementedError(
        "Customize this harness with the actual agent import."
    )


async def invoke_agent(prompt: str) -> str:
    """Send a prompt to the agent and return the response."""
    agent = await create_agent()
    result = agent.kickoff(inputs={{"query": prompt}})
    return str(result)


async def main():
    """Run the harness with a test prompt."""
    response = await invoke_agent("Hello, what can you do?")
    print(f"Response: {{response}}")


if __name__ == "__main__":
    asyncio.run(main())
'''
    return HarnessOutput(
        framework="crewai",
        script=script,
        filename="harness_crewai.py",
    )


def generate_adk_harness(agent_files: list[str]) -> HarnessOutput:
    """Generate a Google ADK agent test harness.

    Args:
        agent_files: List of file paths containing agent definitions.

    Returns:
        HarnessOutput with the executable test script.
    """
    imports = "\n".join(f'# Agent file: {f}' for f in agent_files)
    script = f'''"""Auto-generated Google ADK agent test harness."""

import asyncio
import sys
sys.path.insert(0, ".")

{imports}

from google.adk.runners import InMemoryRunner
from google.adk.sessions import InMemorySessionService
from google.genai import types


async def create_runner():
    """Instantiate the ADK agent runner from discovered files."""
    # TODO: Auto-detect and import the agent from agent_files
    raise NotImplementedError(
        "Customize this harness with the actual agent import."
    )


async def invoke_agent(prompt: str) -> str:
    """Send a prompt to the agent and return the response."""
    runner = await create_runner()
    session_service = InMemorySessionService()
    session = await session_service.create_session(
        app_name="test_harness", user_id="red_team"
    )
    content = types.Content(
        role="user",
        parts=[types.Part(text=prompt)],
    )
    response_parts: list[str] = []
    async for event in runner.run_async(
        user_id="red_team",
        session_id=session.id,
        new_message=content,
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    response_parts.append(part.text)
    return "".join(response_parts)


async def main():
    """Run the harness with a test prompt."""
    response = await invoke_agent("Hello, what can you do?")
    print(f"Response: {{response}}")


if __name__ == "__main__":
    asyncio.run(main())
'''
    return HarnessOutput(
        framework="adk",
        script=script,
        filename="harness_adk.py",
    )


def generate_openai_harness(agent_files: list[str]) -> HarnessOutput:
    """Generate an OpenAI Agents SDK test harness.

    Args:
        agent_files: List of file paths containing agent definitions.

    Returns:
        HarnessOutput with the executable test script.
    """
    imports = "\n".join(f'# Agent file: {f}' for f in agent_files)
    script = f'''"""Auto-generated OpenAI Agents SDK test harness."""

import asyncio
import sys
sys.path.insert(0, ".")

{imports}

from agents import Agent, Runner


async def create_agent():
    """Instantiate the OpenAI agent from discovered files."""
    # TODO: Auto-detect and import the agent from agent_files
    raise NotImplementedError(
        "Customize this harness with the actual agent import."
    )


async def invoke_agent(prompt: str) -> str:
    """Send a prompt to the agent and return the response."""
    agent = await create_agent()
    result = await Runner.run(agent, prompt)
    return result.final_output


async def main():
    """Run the harness with a test prompt."""
    response = await invoke_agent("Hello, what can you do?")
    print(f"Response: {{response}}")


if __name__ == "__main__":
    asyncio.run(main())
'''
    return HarnessOutput(
        framework="openai_agents",
        script=script,
        filename="harness_openai.py",
    )
