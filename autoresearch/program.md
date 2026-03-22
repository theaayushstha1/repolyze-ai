# RepolyzeAI — Autoresearch Program

## Goal
Continuously improve RepolyzeAI's security scanning rules to maximize detection of real vulnerabilities while minimizing false positives.

## Instructions
You are improving the security detection rules in `scan_rules.py`. Each iteration:

1. Read the current rules and the results log from previous experiments
2. Make ONE focused change to improve detection:
   - Add a new detection pattern (regex, AST pattern, or heuristic)
   - Refine an existing pattern to reduce false positives
   - Adjust severity classifications
   - Add new categories of checks (agent safety, MCP, supply chain)
3. Run the evaluation against the test suite of known-vulnerable repos
4. If the detection score improves → keep the change
5. If the score drops or stays same → discard the change

## What to Explore
- New regex patterns for detecting vulnerabilities (SQL injection, XSS, SSRF, etc.)
- Better agent safety heuristics (detecting missing guardrails more accurately)
- MCP tool permission patterns (new dangerous operations to flag)
- Secret detection patterns (new API key formats, token patterns)
- Reducing false positives on common safe patterns (test files, examples, comments)
- Adding CWE mappings to findings for better categorization

## Constraints
- Do NOT modify `evaluate.py` — it is the fixed evaluation harness
- Keep `scan_rules.py` under 500 lines
- Each rule must include: pattern, severity, category, message, remediation
- Patterns must be valid Python regex
- Do not add rules that match on comments or docstrings only
- Maintain backward compatibility with existing rule format

## Metric
`detection_score = (true_positives * 10) - (false_positives * 5) + (severity_accuracy * 3)`

Higher is better. The score measures:
- True positives: real vulnerabilities correctly flagged
- False positives: safe code incorrectly flagged (penalized heavily)
- Severity accuracy: correct severity classification

## Stopping Criteria
- Stop after 50 experiments per session
- Or when no improvement for 10 consecutive iterations
- Or when detection_score > 500
