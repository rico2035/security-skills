#!/usr/bin/env python3
"""
Security hook for Claude Code. Runs as a PreToolUse hook on
Edit/Write/MultiEdit/NotebookEdit.

Reads the hook payload from stdin (JSON with tool_name and tool_input),
scans the content about to be written, and returns a permission decision:
  - "deny" for real secret material (API keys, private keys)
  - "ask"  for PHI/PII in logging statements and injection-prone patterns

Requires Python 3.9+ available as python3 on PATH.
"""

import fnmatch
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone

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
    (r'\bsk-proj-[a-zA-Z0-9\-_]{20,}', 'OpenAI project API key detected'),
    (r'\bsk-or-[a-zA-Z0-9\-_]{20,}', 'OpenRouter API key detected'),
    (r'\bsk-[a-zA-Z0-9]{20,}', 'Possible API key (sk-...) detected'),
    (r'\b[sr]k_(live|test)_[a-zA-Z0-9]{20,}', 'Stripe secret or restricted key detected'),
    (r'\bAKIA[0-9A-Z]{16}\b', 'AWS Access Key ID detected'),
    (r'\bAIza[0-9A-Za-z\-_]{35}\b', 'Google API key detected'),
    (r'\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}', 'SendGrid API key detected'),
    (r'\bghp_[a-zA-Z0-9]{36}\b', 'GitHub personal access token detected'),
    (r'\bgho_[a-zA-Z0-9]{36}\b', 'GitHub OAuth token detected'),
    (r'\bgithub_pat_[A-Za-z0-9_]{22,}', 'GitHub fine-grained personal access token detected'),
    (r'\bglpat-[a-zA-Z0-9\-_]{20,}', 'GitLab personal access token detected'),
    (r'\bnpm_[a-zA-Z0-9]{36}\b', 'npm access token detected'),
    (r'\bxox[abcpes]-[a-zA-Z0-9\-]{10,}', 'Slack token detected'),
    (r'\bwhsec_[a-zA-Z0-9]{20,}', 'Stripe webhook secret detected'),
    (r'\bsb_secret_[A-Za-z0-9_\-]{20,}', 'Supabase secret key detected'),
    # A JWT whose payload contains "service_role" (base64 at any of the three
    # alignment offsets). Anon/publishable JWTs are public and stay allowed.
    (r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*(c2VydmljZV9yb2xl|NlcnZpY2Vfcm9sZ|zZXJ2aWNlX3JvbGU)[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+',
     'Supabase service_role JWT detected'),
    (r'-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE KEY', 'Private key detected'),
]

# Connection strings get their own check so interpolated or placeholder
# passwords (e.g. postgres://user:${DB_PASSWORD}@host) do not hard-block.
CONN_STRING_RE = re.compile(
    r'\b(mongodb(?:\+srv)?|postgres|postgresql|mysql|redis|amqp)://[\w.\-]+:([^@\s]+)@'
)
CONN_PLACEHOLDER_RE = re.compile(
    r'[${%<]'                       # ${VAR}, %s, <password>
    r'|^(?:password|passwd|pass|secret|changeme|example|xxx+|\*+|your[-_]?\w*)$',
    re.IGNORECASE,
)


def scan_connection_strings(content: str) -> list:
    """Flag connection strings only when the password part looks real."""
    for match in CONN_STRING_RE.finditer(content):
        password = match.group(2)
        if not CONN_PLACEHOLDER_RE.search(password):
            return ['Connection string with embedded credentials detected']
    return []

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
    if tool_name == "NotebookEdit":
        return tool_input.get("new_source", "") or ""
    # Unknown tool: scan the most likely fields.
    return (tool_input.get("content", "") or tool_input.get("new_string", "")
            or tool_input.get("new_source", "") or "")


def is_test_path(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/").lower()
    return any(fnmatch.fnmatch(normalized, g) for g in TEST_PATH_GLOBS)


# --- Foundri hook-event logging ---

def _hook_log_path() -> str:
    """Sink path from FOUNDRI_HOOK_LOG, default ~/.foundri/hook-events.jsonl."""
    override = os.environ.get("FOUNDRI_HOOK_LOG")
    if override:
        return os.path.expanduser(override)
    return os.path.join(os.path.expanduser("~"), ".foundri", "hook-events.jsonl")


def _git_actor() -> str:
    """Git user email if resolvable, else 'local'."""
    try:
        out = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True, text=True, timeout=2,
        )
        email = (out.stdout or "").strip()
        return email if out.returncode == 0 and email else "local"
    except Exception:
        return "local"


def _masked(message: str) -> str:
    """Derive a redacted descriptor from a rule message.

    Rule messages never contain the matched text, so the descriptor is safe;
    we only normalize the wording to make the redaction explicit. Live secret
    material is never written to the sink.
    """
    if message.endswith(" detected"):
        return message[: -len(" detected")] + " (redacted)"
    return message + " (redacted)"


def log_decision(decision: str, rules: list, tool_name: str, file_path: str) -> None:
    """Append one JSON line per decision to the Foundri hook-event sink.

    decision: "block" | "ask" | "allow". rules: matched rule messages (empty
    for allow). Fail open: any logging error is swallowed so a sink problem
    can never block the user's edit.
    """
    try:
        path = _hook_log_path()
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        record = {
            "id": uuid.uuid4().hex,
            "decision": decision,
            "rule": rules[0] if rules else None,
            "tool": tool_name,
            "file_path": file_path,
            "match": _masked(rules[0]) if rules else None,
            "actor": _git_actor(),
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass


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
    blockers += scan_connection_strings(content)

    warnings = []
    if not is_test_path(file_path):
        warnings += scan(PHI_LOG_PATTERNS, content, ignorecase=True)
    warnings += scan(INJECTION_PATTERNS, content, ignorecase=False)

    if blockers:
        reason = "SECURITY: blocked. " + "; ".join(blockers) + \
            ". Move secrets to environment variables and rotate any exposed key."
        decision = "deny"
        log_decision("block", blockers, tool_name, file_path)
    elif warnings:
        reason = "SECURITY: review needed. " + "; ".join(warnings)
        decision = "ask"
        log_decision("ask", warnings, tool_name, file_path)
    else:
        log_decision("allow", [], tool_name, file_path)
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
