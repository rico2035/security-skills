# Security Skills

Security and compliance audit skills for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Scans your codebase for vulnerabilities, PHI/PII leaks, hardcoded secrets, tenant isolation failures, and compliance gaps across HIPAA, SOC 2, OWASP, HITRUST, FDCPA/TCPA, and PQC standards.

## Installation

### Option 1: Claude Code Plugin (Recommended)

```bash
# Add the marketplace
claude plugin marketplace add rico2035/security-skills

# Install the security audit plugin
claude plugin install security-audit@rico2035-security-skills
```

Restart Claude Code after installation. This gives you:
- `/security-audit` slash command
- Real-time security hooks on Edit/Write operations
- Auto-updates via marketplace

### Option 2: Git Submodule (Fallback)

```bash
# Add as submodule
git submodule add https://github.com/rico2035/security-skills.git

# Run setup (copies command to .claude/commands/)
./security-skills/setup.sh        # Unix/Mac
.\security-skills\setup.ps1       # Windows
```

## Usage

```
/security-audit              # Full audit (all modules)
/security-audit hipaa        # PHI/PII leak detection
/security-audit owasp        # OWASP Top 10 scan
/security-audit secrets      # Secrets & config audit
/security-audit tenant       # Tenant isolation check
/security-audit audit-trail  # Audit trail completeness
/security-audit pqc          # PQC cryptography audit
/security-audit fdcpa        # FDCPA/TCPA compliance
/security-audit hitrust      # HITRUST CSF status
/security-audit pre-deploy   # Pre-deployment security gate
```

## Modules

### Universal (enabled by default)

| Module | What it checks |
|--------|----------------|
| **PHI/PII Detection** | Sensitive data in logs, errors, API responses |
| **OWASP Top 10** | Injection, XSS, auth bypass, SSRF, weak crypto, and more |
| **Secrets Audit** | Hardcoded API keys, passwords, private keys, connection strings |
| **Tenant Isolation** | Multi-tenant data segregation across all database queries |
| **Audit Trail** | Completeness of security event logging |

### Industry-Specific (opt-in)

| Module | When to enable |
|--------|----------------|
| **PQC Crypto** | Projects using post-quantum cryptography (FIPS 203/204/205) |
| **FDCPA/TCPA** | Debt collection or automated consumer communications |
| **HITRUST CSF** | Healthcare projects targeting enterprise certification |

## Stack Auto-Detection

The skill auto-detects your project's technology stack and tailors search patterns accordingly:

- **Languages:** TypeScript, JavaScript, Python, Go, Java, Ruby, Rust
- **Frameworks:** NestJS, Express, FastAPI, Django, Spring Boot, Rails
- **ORMs:** Prisma, TypeORM, Sequelize, SQLAlchemy, Django ORM

## Compliance Coverage

| Framework | Key Checks |
|-----------|-----------|
| HIPAA Security Rule | PHI leak detection, audit trails, encryption, access controls |
| SOC 2 Type II | Logical access, monitoring, logging, change management |
| OWASP Top 10 (2021) | All 10 vulnerability categories |
| HITRUST CSF | 19 domains, 156+ controls |
| FDCPA / Reg F | Call restrictions, consent tracking, DNC compliance |
| TCPA | Automated communications consent and revocation |
| FIPS 203/204/205 | ML-KEM, ML-DSA, SLH-DSA implementation verification |

## Report Format

The audit produces a structured report with:
- Executive summary (finding counts by severity)
- Per-module results (PASS / WARN / FAIL)
- Compliance scorecard (% compliant per framework)
- Priority remediation queue (ordered by severity)
- Actionable fix guidance with file locations

## Real-Time Hooks

When installed as a plugin, a `PreToolUse` hook runs on every `Edit` and `Write` operation, catching:
- PHI/PII in logging statements
- Hardcoded secrets and API keys
- Injection-prone patterns (`eval`, `innerHTML`, `$queryRawUnsafe`)

## License

MIT
