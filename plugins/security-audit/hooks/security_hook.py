#!/usr/bin/env python3
"""
Security hook for Claude Code. Runs as a PreToolUse hook on Edit/Write/MultiEdit.

Reads the hook payload from stdin (JSON with tool_name and tool_input),
scans the content about to be written, and returns a permission decision:
  - "deny" for real secret material (API keys, private keys)
  - "ask"  for PHI/PII in logging statements and injection-prone patterns

Requires Python 3.9+ available as python3 on PATH.
"""

import fnmatch
import json
import re
import sys

# Paths where PHI/PII and password patterns are expected (test data, fixtures).
# Secret-material patterns still apply everywhere.
TEST_PATH_GLOBS = [
    "*.test.*", "*.spec.*", "*fixture*", "*mock*", "*seed*",
    "*__tests__*", "*__mocks__*", "*security_hook*",
]

# --- Patterns ---

# Hard block: real secret material. permissionDecision = deny.
SECRET_PATTERNS = [
    (r'\bsk-ant-[a-zA-Z0-9\-_]{20,}', 'Anthropic API key detected'),
    (r'\bsk-[a-zA-Z0-9]{20,}', 'Possible API key (sk-...) detected'),
    (r'\bAKIA[0-9A-Z]{16}\b', 'AWS Access Key ID detected'),
    (r'\bghp_[a-zA-Z0-9]{36}\b', 'GitHub personal access token detected'),
    (r'\bgho_[a-zA-Z0-9]{36}\b', 'GitHub OAuth token detected'),
    (r'\bglpat-[a-zA-Z0-9\-_]{20,}', 'GitLab personal access token detected'),
    (r'\bxox[bpas]-[a-zA-Z0-9\-]{10,}', 'Slack token detected'),
    (r'\bwhsec_[a-zA-Z0-9]{20,}', 'Stripe webhook secret detected'),
    (r'-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY', 'Private key detected'),
    (r'(mongodb|postgres|postgresql|mysql|redis)://\w+:[^@\s]+@', 'Connection string with embedded credentials detected'),
]

# Ask for confirmation: likely PHI/PII in logs. permissionDecision = ask.
# Skipped for test/fixture/mock paths.
PHI_LOG_PATTERNS = [
    (r'console\.(log|warn|error|info|debug)\(.*\b(patient|ssn|dob|diagnosis|creditCard|bankAccount|socialSecurity|dateOfBirth|insuranceId)\b',
     'Possible PHI/PII in console output'),
    (r'logger\.\w+\(.*\b(patient(Name|Id|SSN|DOB)|ssn|socialSecurity|dateOfBirth|diagnosis)\b',
     'Possible PHI/PII in logger statement'),
    (r'logging\.\w+\(.*\b(patient|ssn|dob|diagnosis|credit_card|bank_account)\b',
     'Possible PHI/PII in Python logging'),
    (r'print\(.*\b(patient|ssn|dob|diagnosis)\b',
     'Possible PHI/PII in print statement'),
    (r'(password|passwd|pwd|secret)\s*[:=]\s*["\'][^"\']{8,}["\']',
     'Possible hardcoded password or secret'),
]

# Ask for confirmation: injection-prone constructs. permissionDecision = ask.
INJECTION_PATTERNS = [
    (r'\beval\s*\(', 'eval() usage, potential code injection'),
    (r'\bnew\s+Function\s*\(', 'new Function() usage, potential code injection'),
    (r'\$queryRawUnsafe|\$executeRawUnsafe', 'Prisma unsafe raw query, potential SQL injection'),
    (r'\.innerHTML\s*=', 'innerHTML assignment, potential XSS'),
    (r'dangerouslySetInnerHTML', 'dangerouslySetInnerHTML usage, potential XSS'),
    (r'document\.write\s*\(', 'document.write() usage, potential XSS'),
    (r'subprocess\.(call|run|Popen)\(.*shell\s*=\s*True', 'subprocess with shell=True, potential command injection'),
    (r'\bos\.system\s*\(', 'os.system() usage, potential command injection'),
]


def extract_content(tool_name: str, tool_input: dict) -> str:
    """Pull the text about to be written from the tool input."""
    if tool_name == "Write":
        return tool_input.get("content", "") or ""
    if tool_name == "Edit":
        return tool_input.get("new_string", "") or ""
    if tool_name == "MultiEdit":
        edits = tool_input.get("edits", []) or []
        return "\n".join(e.get("new_string", "") or "" for e in edits if isinstance(e, dict))
    # Unknown tool: scan the most likely fields.
    return tool_input.get("content", "") or tool_input.get("new_string", "") or ""


def is_test_path(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/").lower()
    return any(fnmatch.fnmatch(normalized, g) for g in TEST_PATH_GLOBS)


def scan(patterns, content: str, ignorecase: bool) -> list:
    flags = re.IGNORECASE if ignorecase else 0
    return [msg for pat, msg in patterns if re.search(pat, content, flags)]


def main():
    try:
        data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {}) or {}
    if not isinstance(tool_input, dict):
        sys.exit(0)

    content = extract_content(tool_name, tool_input)
    if not content:
        sys.exit(0)

    file_path = tool_input.get("file_path", "") or ""

    # Secret material is case-sensitive on purpose: key prefixes are exact.
    blockers = scan(SECRET_PATTERNS, content, ignorecase=False)

    warnings = []
    if not is_test_path(file_path):
        warnings += scan(PHI_LOG_PATTERNS, content, ignorecase=True)
    warnings += scan(INJECTION_PATTERNS, content, ignorecase=False)

    if blockers:
        reason = "SECURITY: blocked. " + "; ".join(blockers) + \
            ". Move secrets to environment variables and rotate any exposed key."
        decision = "deny"
    elif warnings:
        reason = "SECURITY: review needed. " + "; ".join(warnings)
        decision = "ask"
    else:
        sys.exit(0)

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


if __name__ == "__main__":
    main()
