"""Fixed evaluation harness — the autoresearch agent CANNOT modify this.

Tests scan_rules.py against a suite of known-vulnerable code snippets
and calculates a detection score. Higher score = better rules.

Metric: detection_score = (true_positives * 10) - (false_positives * 5) + (severity_accuracy * 3)
"""

from __future__ import annotations

import importlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Test Cases ─────────────────────────────────────────────────────────────
# Each case: (code, expected_findings). expected_findings is a list of
# {category, severity} dicts that SHOULD be detected.

VULNERABLE_SAMPLES: list[dict[str, Any]] = [
    {
        "name": "sql_injection_format",
        "code": 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
        "file_ext": ".py",
        "expected": [{"category": "injection", "severity": "CRITICAL"}],
    },
    {
        "name": "sql_injection_fstring",
        "code": 'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
        "file_ext": ".py",
        "expected": [{"category": "injection", "severity": "CRITICAL"}],
    },
    {
        "name": "os_system_injection",
        "code": 'os.system(f"ping {user_input}")',
        "file_ext": ".py",
        "expected": [{"category": "injection", "severity": "CRITICAL"}],
    },
    {
        "name": "subprocess_shell_true",
        "code": 'subprocess.run(cmd, shell=True)',
        "file_ext": ".py",
        "expected": [{"category": "injection", "severity": "HIGH"}],
    },
    {
        "name": "xss_innerhtml",
        "code": 'element.innerHTML = userInput;',
        "file_ext": ".js",
        "expected": [{"category": "xss", "severity": "HIGH"}],
    },
    {
        "name": "xss_dangerously",
        "code": '<div dangerouslySetInnerHTML={{__html: data}} />',
        "file_ext": ".jsx",
        "expected": [{"category": "xss", "severity": "HIGH"}],
    },
    {
        "name": "hardcoded_aws_key",
        "code": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        "file_ext": ".py",
        "expected": [{"category": "secret_leak", "severity": "CRITICAL"}],
    },
    {
        "name": "hardcoded_openai_key",
        "code": 'api_key = "sk-abc123def456ghi789jkl012mno345pqr678"',
        "file_ext": ".py",
        "expected": [{"category": "secret_leak", "severity": "CRITICAL"}],
    },
    {
        "name": "hardcoded_github_token",
        "code": 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"',
        "file_ext": ".py",
        "expected": [{"category": "secret_leak", "severity": "CRITICAL"}],
    },
    {
        "name": "md5_hashing",
        "code": 'password_hash = hashlib.md5(password.encode()).hexdigest()',
        "file_ext": ".py",
        "expected": [{"category": "crypto", "severity": "MEDIUM"}],
    },
    {
        "name": "eval_user_input",
        "code": 'result = eval(request.data)',
        "file_ext": ".py",
        "expected": [{"category": "agent_safety", "severity": "CRITICAL"}],
    },
    {
        "name": "pickle_load",
        "code": 'data = pickle.loads(request.body)',
        "file_ext": ".py",
        "expected": [{"category": "deserialization", "severity": "CRITICAL"}],
    },
    {
        "name": "yaml_unsafe_load",
        "code": 'config = yaml.load(open("config.yml"))',
        "file_ext": ".py",
        "expected": [{"category": "deserialization", "severity": "HIGH"}],
    },
    {
        "name": "ssrf_requests",
        "code": 'response = requests.get(request.args["url"])',
        "file_ext": ".py",
        "expected": [{"category": "ssrf", "severity": "HIGH"}],
    },
    {
        "name": "path_traversal",
        "code": 'f = open(request.args["file"])',
        "file_ext": ".py",
        "expected": [{"category": "path_traversal", "severity": "HIGH"}],
    },
]

# Safe code that should NOT be flagged (false positive tests)
SAFE_SAMPLES: list[dict[str, Any]] = [
    {
        "name": "safe_parameterized_query",
        "code": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "file_ext": ".py",
    },
    {
        "name": "safe_subprocess_list",
        "code": 'subprocess.run(["ls", "-la"], capture_output=True)',
        "file_ext": ".py",
    },
    {
        "name": "safe_text_content",
        "code": 'element.textContent = userInput;',
        "file_ext": ".js",
    },
    {
        "name": "safe_env_var",
        "code": 'api_key = os.environ["API_KEY"]',
        "file_ext": ".py",
    },
    {
        "name": "safe_sha256",
        "code": 'password_hash = hashlib.sha256(password.encode()).hexdigest()',
        "file_ext": ".py",
    },
    {
        "name": "safe_yaml",
        "code": 'config = yaml.safe_load(open("config.yml"))',
        "file_ext": ".py",
    },
    {
        "name": "safe_test_file",
        "code": '# test_example.py\napi_key = "sk-test-fake-key-for-testing-only"',
        "file_ext": ".py",
    },
    {
        "name": "safe_json_parse",
        "code": 'data = json.loads(request.body)',
        "file_ext": ".py",
    },
]


def _load_rules() -> list[dict]:
    """Dynamically reload scan_rules.py to pick up changes."""
    rules_path = Path(__file__).parent / "scan_rules.py"
    spec = importlib.util.spec_from_file_location("scan_rules", rules_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.RULES


def _match_rules(code: str, file_ext: str, rules: list[dict]) -> list[dict]:
    """Run all rules against a code snippet and return matches."""
    matches = []
    for rule in rules:
        scope = rule.get("scope", "all")
        if scope != "all":
            ext_map = {
                "python": [".py"],
                "javascript": [".js", ".jsx", ".ts", ".tsx"],
                "agent": [".py"],
                "mcp": [".py"],
            }
            if file_ext not in ext_map.get(scope, [file_ext]):
                continue

        excludes = rule.get("exclude_in", [])
        if any(exc in code for exc in excludes if exc):
            continue

        try:
            if re.search(rule["pattern"], code, re.MULTILINE):
                matches.append({
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "message": rule["message"],
                })
        except re.error:
            continue

    return matches


def evaluate() -> dict[str, Any]:
    """Run the full evaluation and return the score."""
    rules = _load_rules()

    true_positives = 0
    false_negatives = 0
    false_positives = 0
    severity_correct = 0
    severity_total = 0
    details: list[str] = []

    # Test vulnerable samples (should be detected)
    for sample in VULNERABLE_SAMPLES:
        matches = _match_rules(sample["code"], sample["file_ext"], rules)
        expected = sample["expected"]

        for exp in expected:
            severity_total += 1
            found = False
            for m in matches:
                if m["category"] == exp["category"]:
                    found = True
                    true_positives += 1
                    if m["severity"] == exp["severity"]:
                        severity_correct += 1
                    details.append(f"  TP: {sample['name']} -> {m['category']}:{m['severity']}")
                    break
            if not found:
                false_negatives += 1
                details.append(f"  FN: {sample['name']} — expected {exp['category']} NOT detected")

    # Test safe samples (should NOT be detected)
    for sample in SAFE_SAMPLES:
        matches = _match_rules(sample["code"], sample["file_ext"], rules)
        if matches:
            false_positives += len(matches)
            for m in matches:
                details.append(f"  FP: {sample['name']} — FALSE POSITIVE: {m['category']}")
        else:
            details.append(f"  TN: {sample['name']} — correctly ignored (safe)")

    # Calculate score
    severity_accuracy = (severity_correct / severity_total * 100) if severity_total > 0 else 0
    detection_score = (true_positives * 10) - (false_positives * 5) + (severity_accuracy * 3)

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_rules": len(rules),
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "severity_correct": severity_correct,
        "severity_total": severity_total,
        "severity_accuracy": round(severity_accuracy, 1),
        "detection_score": round(detection_score, 1),
        "detection_rate": round(true_positives / (true_positives + false_negatives) * 100, 1) if (true_positives + false_negatives) > 0 else 0,
    }

    return result, details


def main():
    """Run evaluation and print results."""
    result, details = evaluate()

    print("\n" + "=" * 60)
    print("  RepolyzeAI Autoresearch — Evaluation Results")
    print("=" * 60)
    print(f"  Rules:              {result['total_rules']}")
    print(f"  True Positives:     {result['true_positives']}")
    print(f"  False Negatives:    {result['false_negatives']}")
    print(f"  False Positives:    {result['false_positives']}")
    print(f"  Detection Rate:     {result['detection_rate']}%")
    print(f"  Severity Accuracy:  {result['severity_accuracy']}%")
    print(f"  DETECTION SCORE:    {result['detection_score']}")
    print("=" * 60)

    print("\nDetails:")
    for d in details:
        print(d)

    # Append to results log
    results_file = Path(__file__).parent / "results.tsv"
    header = not results_file.exists()
    with open(results_file, "a") as f:
        if header:
            f.write("timestamp\trules\ttp\tfn\tfp\tdetection_rate\tseverity_accuracy\tscore\n")
        f.write(
            f"{result['timestamp']}\t{result['total_rules']}\t"
            f"{result['true_positives']}\t{result['false_negatives']}\t"
            f"{result['false_positives']}\t{result['detection_rate']}\t"
            f"{result['severity_accuracy']}\t{result['detection_score']}\n"
        )

    return result


if __name__ == "__main__":
    main()
