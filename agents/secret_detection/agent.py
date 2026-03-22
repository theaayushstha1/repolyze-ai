"""SecretDetectionAgent — scans repositories for leaked secrets.

Uses TruffleHog to detect hardcoded API keys, passwords, tokens,
and other sensitive credentials in source code and git history.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent

from agents.secret_detection.tools import trufflehog_scan


MODEL = "gemini-2.5-flash"

INSTRUCTION = """You are a secret detection security agent. Your job is to:

1. Run trufflehog_scan on the repository to detect leaked secrets.
2. Classify each finding by type (API key, password, token, private key, etc.).
3. Assess the risk level based on the secret type and exposure context.

Each finding must include:
- file_path: where the secret was found
- line_number: the line number
- secret_type: type of secret (api_key, password, token, private_key, etc.)
- severity: critical / high / medium / low
- detector: which detector matched (e.g., AWS, GitHub, Generic)
- verified: whether TruffleHog verified the secret is active
- redacted_value: a safely redacted version of the secret

IMPORTANT:
- Always redact actual secret values — never output raw secrets.
- Verified active secrets are CRITICAL severity.
- Secrets in test fixtures or example files are LOW severity.
- Do NOT fabricate findings — only report what the tool returns.
"""

secret_detection_agent = LlmAgent(
    name="SecretDetectionAgent",
    model=MODEL,
    instruction=INSTRUCTION,
    tools=[trufflehog_scan],
)
