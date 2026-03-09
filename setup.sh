#!/bin/bash

# Security Skills — Submodule Fallback Installer
# For full features (hooks, agents, auto-update), use the plugin system instead:
#   claude plugin marketplace add rico2035/security-skills
#   claude plugin install security-audit@rico2035-security-skills

set -e

echo "========================================"
echo "  Security Skills Installer"
echo "  Security & Compliance Audit Toolkit"
echo "========================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create .claude/commands if it doesn't exist
mkdir -p .claude/commands

# Copy the main security-audit command
cp "$SCRIPT_DIR/plugins/security-audit/commands/security-audit.md" .claude/commands/security-audit.md

echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo ""
echo "Installed:"
echo "  - .claude/commands/security-audit.md"
echo ""
echo "Usage:"
echo "  /security-audit              Full audit"
echo "  /security-audit hipaa        PHI/PII scan"
echo "  /security-audit owasp        OWASP Top 10"
echo "  /security-audit secrets      Secrets scan"
echo "  /security-audit tenant       Tenant isolation"
echo "  /security-audit audit-trail  Audit trail check"
echo "  /security-audit pqc          PQC crypto audit"
echo "  /security-audit fdcpa        FDCPA/TCPA compliance"
echo "  /security-audit hitrust      HITRUST CSF status"
echo "  /security-audit pre-deploy   Pre-deployment gate"
echo ""
echo "For full features (hooks, auto-update), use the plugin system:"
echo "  claude plugin marketplace add rico2035/security-skills"
echo "  claude plugin install security-audit@rico2035-security-skills"
echo ""
