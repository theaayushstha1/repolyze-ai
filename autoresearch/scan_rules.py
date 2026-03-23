"""Mutable scan rules — the autoresearch agent improves these.

This is the equivalent of Karpathy's train.py — the ONLY file the
autoresearch loop modifies. Each rule is a detection pattern that
gets tested against known-vulnerable repos.

Format: each rule is a dict with:
  - pattern: regex string
  - severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
  - category: OWASP or custom category
  - cwe: CWE ID (optional)
  - message: human-readable description
  - remediation: how to fix
  - scope: "all" | "python" | "javascript" | "agent" | "mcp"
  - exclude_in: list of patterns to NOT match (reduce false positives)
"""

from __future__ import annotations

RULES: list[dict[str, str | list[str]]] = [
    # ── Injection ──────────────────────────────────────────────────────
    {
        "pattern": r"execute\s*\(\s*[\"'].*%s.*[\"']\s*%\s",
        "severity": "CRITICAL",
        "category": "injection",
        "cwe": "CWE-89",
        "message": "SQL injection via string formatting",
        "remediation": "Use parameterized queries",
        "scope": "python",
        "exclude_in": ["test_", "example", "#"],
    },
    {
        "pattern": r"cursor\.\s*execute\s*\(\s*f[\"']",
        "severity": "CRITICAL",
        "category": "injection",
        "cwe": "CWE-89",
        "message": "SQL injection via f-string in cursor.execute",
        "remediation": "Use parameterized queries with placeholders",
        "scope": "python",
        "exclude_in": ["test_", "mock"],
    },
    {
        "pattern": r"\.raw\s*\(\s*f?[\"'].*\{",
        "severity": "HIGH",
        "category": "injection",
        "cwe": "CWE-89",
        "message": "Raw SQL query with string interpolation (ORM bypass)",
        "remediation": "Use ORM query builder with parameterized inputs",
        "scope": "python",
        "exclude_in": ["test_"],
    },

    # ── Command Injection ──────────────────────────────────────────────
    {
        "pattern": r"os\.system\s*\(\s*f?[\"'].*\{",
        "severity": "CRITICAL",
        "category": "injection",
        "cwe": "CWE-78",
        "message": "OS command injection via string interpolation",
        "remediation": "Use subprocess with argument list, never shell=True with user input",
        "scope": "all",
        "exclude_in": [],
    },
    {
        "pattern": r"subprocess\.\w+\(.*shell\s*=\s*True",
        "severity": "HIGH",
        "category": "injection",
        "cwe": "CWE-78",
        "message": "Subprocess with shell=True enables command injection",
        "remediation": "Use subprocess with shell=False and pass arguments as a list",
        "scope": "python",
        "exclude_in": [],
    },

    # ── XSS ────────────────────────────────────────────────────────────
    {
        "pattern": r"innerHTML\s*=",
        "severity": "HIGH",
        "category": "xss",
        "cwe": "CWE-79",
        "message": "innerHTML assignment enables XSS",
        "remediation": "Use textContent or a sanitization library like DOMPurify",
        "scope": "javascript",
        "exclude_in": [],
    },
    {
        "pattern": r"dangerouslySetInnerHTML",
        "severity": "HIGH",
        "category": "xss",
        "cwe": "CWE-79",
        "message": "dangerouslySetInnerHTML in React component",
        "remediation": "Sanitize input with DOMPurify before rendering",
        "scope": "javascript",
        "exclude_in": [],
    },
    {
        "pattern": r"document\.write\s*\(",
        "severity": "MEDIUM",
        "category": "xss",
        "cwe": "CWE-79",
        "message": "document.write can enable XSS",
        "remediation": "Use DOM manipulation methods instead",
        "scope": "javascript",
        "exclude_in": [],
    },

    # ── Secrets ────────────────────────────────────────────────────────
    {
        "pattern": r"(?:api_key|apikey|api_secret|secret_key)\s*=\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
        "severity": "CRITICAL",
        "category": "secret_leak",
        "cwe": "CWE-798",
        "message": "Hardcoded API key or secret",
        "remediation": "Use environment variables or a secret manager",
        "scope": "all",
        "exclude_in": ["test_", "example", "placeholder", "your-"],
    },
    {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "category": "secret_leak",
        "cwe": "CWE-798",
        "message": "AWS Access Key ID detected",
        "remediation": "Rotate the key immediately and use IAM roles or environment variables",
        "scope": "all",
        "exclude_in": [],
    },
    {
        "pattern": r"sk-[a-zA-Z0-9]{20,}",
        "severity": "CRITICAL",
        "category": "secret_leak",
        "cwe": "CWE-798",
        "message": "Possible OpenAI/Stripe secret key",
        "remediation": "Rotate immediately; store in environment variables",
        "scope": "all",
        "exclude_in": ["test", "example", "fake"],
    },
    {
        "pattern": r"ghp_[a-zA-Z0-9]{36}",
        "severity": "CRITICAL",
        "category": "secret_leak",
        "cwe": "CWE-798",
        "message": "GitHub Personal Access Token detected",
        "remediation": "Revoke and regenerate; use GitHub Apps or environment variables",
        "scope": "all",
        "exclude_in": [],
    },

    # ── Crypto Weaknesses ──────────────────────────────────────────────
    {
        "pattern": r"hashlib\.md5\s*\(",
        "severity": "MEDIUM",
        "category": "crypto",
        "cwe": "CWE-328",
        "message": "MD5 used for hashing — cryptographically broken",
        "remediation": "Use SHA-256 or bcrypt for password hashing",
        "scope": "python",
        "exclude_in": ["checksum", "fingerprint"],
    },
    {
        "pattern": r"hashlib\.sha1\s*\(",
        "severity": "MEDIUM",
        "category": "crypto",
        "cwe": "CWE-328",
        "message": "SHA-1 used for hashing — deprecated for security",
        "remediation": "Use SHA-256 or SHA-3",
        "scope": "python",
        "exclude_in": ["git", "checksum"],
    },

    # ── Agent Safety ───────────────────────────────────────────────────
    {
        "pattern": r"eval\s*\(\s*(?:request|input|user|data|body|params|query)",
        "severity": "CRITICAL",
        "category": "agent_safety",
        "cwe": "CWE-95",
        "message": "eval() called with user-controlled input",
        "remediation": "Never eval user input; use ast.literal_eval for safe parsing",
        "scope": "python",
        "exclude_in": [],
    },
    {
        "pattern": r"(LlmAgent|AgentExecutor|CrewBase|ChatOpenAI)(?!.*guardrail)(?!.*safety)(?!.*filter)",
        "severity": "HIGH",
        "category": "agent_safety",
        "cwe": "",
        "message": "AI agent without visible safety guardrails",
        "remediation": "Add input validation, content filtering, and output guardrails",
        "scope": "python",
        "exclude_in": ["test_", "example"],
    },
    {
        "pattern": r"system_prompt.*=.*\{.*user",
        "severity": "HIGH",
        "category": "agent_safety",
        "cwe": "",
        "message": "User input interpolated into system prompt — prompt injection risk",
        "remediation": "Never interpolate raw user input into system prompts",
        "scope": "python",
        "exclude_in": [],
    },

    # ── MCP Security ───────────────────────────────────────────────────
    {
        "pattern": r"@(?:mcp|server)\.tool.*\n(?:(?!.*(?:validate|sanitize|check)).*\n){0,5}.*subprocess",
        "severity": "CRITICAL",
        "category": "mcp_security",
        "cwe": "CWE-78",
        "message": "MCP tool executes shell commands without input validation",
        "remediation": "Add input validation before any shell execution in MCP tools",
        "scope": "python",
        "exclude_in": [],
    },
    {
        "pattern": r"@(?:mcp|server)\.tool.*\n(?:(?!.*(?:validate|sanitize|whitelist|allowlist)).*\n){0,5}.*open\s*\(",
        "severity": "HIGH",
        "category": "mcp_security",
        "cwe": "CWE-22",
        "message": "MCP tool accesses files without path validation",
        "remediation": "Validate file paths against an allowlist of directories",
        "scope": "python",
        "exclude_in": [],
    },

    # ── Path Traversal ─────────────────────────────────────────────────
    {
        "pattern": r"open\s*\(\s*(?:request|input|user|data|params)",
        "severity": "HIGH",
        "category": "path_traversal",
        "cwe": "CWE-22",
        "message": "File opened with user-controlled path — path traversal risk",
        "remediation": "Validate and sanitize file paths; use os.path.realpath to resolve",
        "scope": "python",
        "exclude_in": [],
    },

    # ── SSRF ───────────────────────────────────────────────────────────
    {
        "pattern": r"requests\.\w+\s*\(\s*(?:request|input|user|url|data|params)",
        "severity": "HIGH",
        "category": "ssrf",
        "cwe": "CWE-918",
        "message": "HTTP request with user-controlled URL — SSRF risk",
        "remediation": "Validate URLs against an allowlist; block internal/private IPs",
        "scope": "python",
        "exclude_in": [],
    },

    # ── Deserialization ────────────────────────────────────────────────
    {
        "pattern": r"pickle\.loads?\s*\(",
        "severity": "CRITICAL",
        "category": "deserialization",
        "cwe": "CWE-502",
        "message": "Pickle deserialization — allows arbitrary code execution",
        "remediation": "Use JSON or a safe serialization format; never unpickle untrusted data",
        "scope": "python",
        "exclude_in": [],
    },
    {
        "pattern": r"yaml\.load\s*\([^)]*(?!Loader)",
        "severity": "HIGH",
        "category": "deserialization",
        "cwe": "CWE-502",
        "message": "YAML load without safe loader — code execution risk",
        "remediation": "Use yaml.safe_load() instead of yaml.load()",
        "scope": "python",
        "exclude_in": [],
    },

    # ── exec() with user input ────────────────────────────────────
    {
        "pattern": r"exec\s*\(\s*(?:request|input|user|data|body|params|query)",
        "severity": "CRITICAL",
        "category": "agent_safety",
        "cwe": "CWE-95",
        "message": "exec() called with user-controlled input — arbitrary code execution",
        "remediation": "Never exec user input; use safe parsing alternatives",
        "scope": "python",
        "exclude_in": [],
    },

    # ── SQL injection via string concatenation ────────────────────
    {
        "pattern": r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*(?:\w+)",
        "severity": "CRITICAL",
        "category": "injection",
        "cwe": "CWE-89",
        "message": "SQL injection via string concatenation",
        "remediation": "Use parameterized queries instead of string concatenation",
        "scope": "python",
        "exclude_in": ["test_", "example", "#"],
    },

    # ── NoSQL injection ───────────────────────────────────────────
    {
        "pattern": r"\$where.*(?:user|input|request|data|params|query)",
        "severity": "CRITICAL",
        "category": "injection",
        "cwe": "CWE-943",
        "message": "NoSQL injection via $where with user input",
        "remediation": "Never pass user input to $where; use query operators instead",
        "scope": "python",
        "exclude_in": [],
    },

    # ── Hardcoded crypto IV ───────────────────────────────────────
    {
        "pattern": r"iv\s*=\s*b?[\"'].*[\"'].*\n.*(?:AES|CBC|CTR|GCM)|iv\s*=\s*b?[\"'].*[\"'].*(?:AES|CBC|CTR|GCM)",
        "severity": "HIGH",
        "category": "crypto",
        "cwe": "CWE-329",
        "message": "Hardcoded initialization vector (IV) in crypto operation",
        "remediation": "Generate a random IV using os.urandom() for each encryption",
        "scope": "python",
        "exclude_in": ["test_"],
    },

    # ── Hardcoded password ────────────────────────────────────────
    {
        "pattern": r"(?:password|passwd|pwd)\s*=\s*[\"'][A-Za-z0-9_!@#$%^&*\-]{8,}[\"']",
        "severity": "HIGH",
        "category": "secret_leak",
        "cwe": "CWE-798",
        "message": "Hardcoded password detected",
        "remediation": "Use environment variables or a secrets manager for passwords",
        "scope": "all",
        "exclude_in": ["test_", "example", "placeholder", "mock"],
    },

    # ── Bearer token in code ──────────────────────────────────────
    {
        "pattern": r"Bearer\s+eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "severity": "HIGH",
        "category": "secret_leak",
        "cwe": "CWE-798",
        "message": "Hardcoded Bearer JWT token detected",
        "remediation": "Never hardcode tokens; retrieve dynamically from auth service",
        "scope": "all",
        "exclude_in": ["test_", "example", "mock"],
    },

    # ── SSRF via urllib ───────────────────────────────────────────
    {
        "pattern": r"urllib\.request\.urlopen\s*\(\s*(?:\w*user\w*|\w*url\w*|\w*input\w*|\w*request\w*)",
        "severity": "HIGH",
        "category": "ssrf",
        "cwe": "CWE-918",
        "message": "urllib request with user-controlled URL — SSRF risk",
        "remediation": "Validate URLs against an allowlist; block internal/private IPs",
        "scope": "python",
        "exclude_in": [],
    },

    # ── marshal deserialization ───────────────────────────────────
    {
        "pattern": r"marshal\.loads?\s*\(",
        "severity": "CRITICAL",
        "category": "deserialization",
        "cwe": "CWE-502",
        "message": "marshal deserialization — allows arbitrary code execution",
        "remediation": "Use JSON or a safe serialization format; never unmarshal untrusted data",
        "scope": "python",
        "exclude_in": [],
    },
]
