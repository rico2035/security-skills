#!/usr/bin/env python3
"""
Security hook for Claude Code — runs on Edit/Write tool calls.
Detects PHI/PII in logs, hardcoded secrets, and injection-prone patterns.
Exit code 0 = allow, exit code 2 = block with message.
"""

import json
import re
import sys

# --- Patterns ---

PHI_LOG_PATTERNS = [
    (r'console\.(log|warn|error|info|debug)\(.*\b(patient|ssn|dob|diagnosis|creditCard|bankAccount|socialSecurity|dateOfBirth|insuranceId)\b', 'PHI/PII detected in console output'),
    (r'logger\.\w+\(.*\b(patient(Name|Id|SSN|DOB)|ssn|socialSecurity|dateOfBirth|diagnosis)\b', 'PHI/PII detected in logger statement'),
    (r'logging\.\w+\(.*\b(patient|ssn|dob|diagnosis|credit_card|bank_account)\b', 'PHI/PII detected in Python logging'),
    (r'print\(.*\b(patient|ssn|dob|diagnosis)\b', 'PHI/PII detected in print statement'),
]

SECRET_PATTERNS = [
    (r'(sk-[a-zA-Z0-9]{20,})', 'Possible API key (sk-...) detected'),
    (r'(AKIA[0-9A-Z]{16})', 'AWS Access Key ID detected'),
    (r'(ghp_[a-zA-Z0-9]{36})', 'GitHub personal access token detected'),
    (r'(sk-ant-[a-zA-Z0-9\-]{20,})', 'Anthropic API key detected'),
    (r'-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----', 'Private key detected'),
    (r'(password|passwd|pwd|secret)\s*[:=]\s*["\'][^"\']{8,}["\']', 'Hardcoded password or secret detected'),
]

INJECTION_PATTERNS = [
    (r'\beval\s*\(', 'eval() detected — potential code injection'),
    (r'\bnew\s+Function\s*\(', 'new Function() detected — potential code injection'),
    (r'\$queryRawUnsafe', 'Prisma $queryRawUnsafe — potential SQL injection'),
    (r'\.innerHTML\s*=', 'innerHTML assignment — potential XSS'),
    (r'dangerouslySetInnerHTML', 'dangerouslySetInnerHTML — potential XSS'),
    (r'document\.write\s*\(', 'document.write() — potential XSS'),
    (r'subprocess\.call\(.*shell\s*=\s*True', 'subprocess with shell=True — potential command injection'),
    (r'os\.system\s*\(', 'os.system() — potential command injection'),
]


def check_content(content: str) -> list[str]:
    """Check content against all security patterns. Returns list of warnings."""
    warnings = []

    for pattern, message in PHI_LOG_PATTERNS + SECRET_PATTERNS + INJECTION_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            warnings.append(message)

    return warnings


def main():
    try:
        tool_input = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()
        data = json.loads(tool_input)
    except (json.JSONDecodeError, IndexError):
        sys.exit(0)

    # Extract content from Edit or Write tool input
    content = data.get("content", "") or data.get("new_string", "")

    if not content:
        sys.exit(0)

    warnings = check_content(content)

    if warnings:
        msg = "SECURITY WARNING:\n" + "\n".join(f"  - {w}" for w in warnings)
        print(msg, file=sys.stderr)
        # Exit 2 = block the tool call with the warning message
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
