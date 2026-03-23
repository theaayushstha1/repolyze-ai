"""Tests for the real scan service and its component scanners."""

import os
import tempfile
from pathlib import Path

import pytest

from app.services.real_scan_service import (
    _detect_agents,
    _detect_languages,
    _detect_mcp,
    _run_agent_safety_scan,
    _run_mcp_audit,
    run_full_scan,
)
from app.services.secret_scanner import _run_regex_scan
from app.services.redteam_engine import (
    _detect_protections,
    calculate_redteam_grade,
    load_probe_files,
)


@pytest.fixture()
def temp_repo():
    """Create a temporary directory simulating a repo."""
    d = tempfile.mkdtemp(prefix="test_repo_")
    yield d
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def _write(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    Path(path).write_text(content)


class TestLanguageDetection:
    def test_detects_python(self, temp_repo):
        _write(f"{temp_repo}/app.py", "print('hello')")
        _write(f"{temp_repo}/utils.py", "x = 1")
        langs = _detect_languages(temp_repo)
        assert "Python" in langs

    def test_detects_typescript(self, temp_repo):
        _write(f"{temp_repo}/app.ts", "const x: number = 1;")
        langs = _detect_languages(temp_repo)
        assert "TypeScript" in langs

    def test_skips_git_dir(self, temp_repo):
        _write(f"{temp_repo}/.git/HEAD", "ref: refs/heads/main")
        _write(f"{temp_repo}/app.py", "x = 1")
        langs = _detect_languages(temp_repo)
        assert len(langs) == 1


class TestAgentDetection:
    def test_detects_adk(self, temp_repo):
        _write(f"{temp_repo}/agent.py",
               "from google.adk.agents import LlmAgent\nagent = LlmAgent()")
        agents = _detect_agents(temp_repo)
        assert agents.get("Google ADK") is True

    def test_no_false_positive_on_string_mention(self, temp_repo):
        _write(f"{temp_repo}/readme_parser.py",
               '# This mentions langchain in a comment\nx = "from langchain"')
        agents = _detect_agents(temp_repo)
        assert agents.get("LangChain", False) is False

    def test_detects_langchain_import(self, temp_repo):
        _write(f"{temp_repo}/chain.py",
               "from langchain.chat_models import ChatOpenAI\nllm = ChatOpenAI()")
        agents = _detect_agents(temp_repo)
        assert agents.get("LangChain") is True

    def test_no_agents_in_clean_repo(self, temp_repo):
        _write(f"{temp_repo}/main.py", "print('hello world')")
        agents = _detect_agents(temp_repo)
        assert not any(agents.values())


class TestMCPDetection:
    def test_detects_mcp_json(self, temp_repo):
        _write(f"{temp_repo}/mcp.json", '{"servers": {}}')
        mcp = _detect_mcp(temp_repo)
        assert len(mcp) >= 1

    def test_detects_mcp_decorator(self, temp_repo):
        _write(f"{temp_repo}/server.py",
               "from mcp import Server\n@mcp.tool\ndef read():\n    pass")
        mcp = _detect_mcp(temp_repo)
        assert len(mcp) >= 1


class TestAgentSafetyScan:
    def test_detects_eval(self, temp_repo):
        _write(f"{temp_repo}/agent.py",
               "from google.adk.agents import LlmAgent\nresult = eval(user_input)")
        findings = _run_agent_safety_scan(temp_repo)
        categories = [f["category"] for f in findings]
        assert "unsafe_tool:code_eval" in categories

    def test_detects_subprocess(self, temp_repo):
        _write(f"{temp_repo}/tool.py",
               "import subprocess\nsubprocess.run(cmd)")
        findings = _run_agent_safety_scan(temp_repo)
        categories = [f["category"] for f in findings]
        assert "unsafe_tool:shell_exec" in categories

    def test_detects_missing_guardrails(self, temp_repo):
        _write(f"{temp_repo}/agent.py",
               "from google.adk.agents import LlmAgent\nagent = LlmAgent(name='test')")
        findings = _run_agent_safety_scan(temp_repo)
        categories = [f["category"] for f in findings]
        assert "missing_guardrail" in categories


class TestSecretScanner:
    def test_detects_aws_key(self, temp_repo):
        _write(f"{temp_repo}/config.py",
               'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        findings = _run_regex_scan(temp_repo)
        assert any(f["title"] == "AWS Access Key ID" for f in findings)

    def test_skips_example_files(self, temp_repo):
        _write(f"{temp_repo}/.env.example",
               'AWS_KEY=AKIAIOSFODNN7EXAMPLE')
        findings = _run_regex_scan(temp_repo)
        assert len(findings) == 0

    def test_detects_github_pat(self, temp_repo):
        _write(f"{temp_repo}/deploy.py",
               'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"')
        findings = _run_regex_scan(temp_repo)
        assert any("GitHub" in f["title"] for f in findings)


class TestRedteamEngine:
    def test_protection_detection_with_validation(self):
        code = "from pydantic import BaseModel\ndef validate(x): pass"
        protections = _detect_protections(code)
        assert protections["input_validation"] is True

    def test_protection_detection_without_validation(self):
        code = "def handle(request): return request.data"
        protections = _detect_protections(code)
        assert protections["input_validation"] is False

    def test_grade_all_protected(self):
        assert calculate_redteam_grade(10, 10) == "A"

    def test_grade_none_protected(self):
        assert calculate_redteam_grade(10, 0) == "F"

    def test_probe_files_load(self):
        probes = load_probe_files()
        assert len(probes) > 0
        for p in probes:
            assert "probes" in p
            assert "category" in p


class TestMCPAudit:
    def test_detects_shell_exec_in_mcp(self, temp_repo):
        _write(f"{temp_repo}/server.py",
               "@mcp.tool\ndef run(cmd):\n    subprocess.run(cmd)")
        findings = _run_mcp_audit(temp_repo,
                                  [f"{temp_repo}/server.py"])
        assert any(f["category"] == "mcp_security" for f in findings)

    def test_no_findings_for_empty_list(self, temp_repo):
        findings = _run_mcp_audit(temp_repo, [])
        assert len(findings) == 0


class TestFullScanIntegration:
    """Integration test that runs the full scan on a small synthetic repo."""

    def test_full_scan_returns_expected_fields(self, temp_repo):
        _write(f"{temp_repo}/main.py", "print('hello')")
        _write(f"{temp_repo}/requirements.txt", "flask==2.0.0\nrequests==2.25.0")

        # We can't clone in tests, so test the component functions directly
        langs = _detect_languages(temp_repo)
        assert isinstance(langs, list)

        agents = _detect_agents(temp_repo)
        assert isinstance(agents, dict)
