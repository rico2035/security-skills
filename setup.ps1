# Security Skills - Submodule Fallback Installer (Windows)
# For full features (hooks, agents, auto-update), use the plugin system instead:
#   claude plugin marketplace add rico2035/security-skills
#   claude plugin install security-audit@rico2035-security-skills

$ErrorActionPreference = "Stop"

Write-Host "========================================"
Write-Host "  Security Skills Installer"
Write-Host "  Security & Compliance Audit Toolkit"
Write-Host "========================================"
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Create .claude/commands if it doesn't exist
if (-not (Test-Path ".claude\commands")) {
    New-Item -ItemType Directory -Path ".claude\commands" -Force | Out-Null
}

# Copy the main security-audit command
Copy-Item "$ScriptDir\plugins\security-audit\commands\security-audit.md" ".claude\commands\security-audit.md"

Write-Host ""
Write-Host "========================================"
Write-Host "  Installation Complete!"
Write-Host "========================================"
Write-Host ""
Write-Host "Installed:"
Write-Host "  - .claude\commands\security-audit.md"
Write-Host ""
Write-Host "Usage:"
Write-Host "  /security-audit              Full audit"
Write-Host "  /security-audit hipaa        PHI/PII scan"
Write-Host "  /security-audit owasp        OWASP Top 10"
Write-Host "  /security-audit secrets      Secrets scan"
Write-Host "  /security-audit tenant       Tenant isolation"
Write-Host "  /security-audit audit-trail  Audit trail check"
Write-Host "  /security-audit pqc          PQC crypto audit"
Write-Host "  /security-audit fdcpa        FDCPA/TCPA compliance"
Write-Host "  /security-audit hitrust      HITRUST CSF status"
Write-Host "  /security-audit pre-deploy   Pre-deployment gate"
Write-Host ""
Write-Host "For full features (hooks, auto-update), use the plugin system:"
Write-Host "  claude plugin marketplace add rico2035/security-skills"
Write-Host "  claude plugin install security-audit@rico2035-security-skills"
Write-Host ""
