# Security Audit Plugin

Comprehensive security and compliance audit toolkit for Claude Code. Scans your codebase for vulnerabilities, compliance gaps, and security misconfigurations.

## Modules

### Universal (enabled by default)

| Module | Skill | What it checks |
|--------|-------|----------------|
| PHI/PII Detection | `phi-pii-detection` | Sensitive data in logs, errors, API responses |
| Tenant Isolation | `tenant-isolation` | Multi-tenant data segregation in all queries |
| OWASP Top 10 | `owasp-top10` | Injection, XSS, auth bypass, SSRF, and more |
| Secrets Audit | `secrets-audit` | Hardcoded API keys, passwords, private keys |
| Audit Trail | `audit-trail` | Completeness of security event logging |

### Industry-Specific (opt-in)

| Module | Skill | When to enable |
|--------|-------|----------------|
| PQC Crypto | `pqc-crypto` | Post-quantum cryptography projects |
| FDCPA/TCPA | `fdcpa-tcpa` | Debt collection / automated communications |
| HITRUST CSF | `hitrust-csf` | Healthcare enterprise certification |

## Commands

```
/security-audit              # Full audit (all enabled modules)
/security-audit hipaa        # PHI/PII focused
/security-audit owasp        # OWASP Top 10
/security-audit secrets      # Secrets scan
/security-audit tenant       # Tenant isolation
/security-audit audit-trail  # Audit trail completeness
/security-audit pqc          # PQC crypto (opt-in)
/security-audit fdcpa        # FDCPA/TCPA (opt-in)
/security-audit hitrust      # HITRUST (opt-in)
/security-audit pre-deploy   # Pre-deployment security gate
```

## Hooks

This plugin includes a `PreToolUse` hook that runs on `Edit` and `Write` operations. It checks for:

- PHI/PII in logging statements
- Hardcoded secrets and API keys
- Injection-prone patterns (`eval`, `innerHTML`, `$queryRawUnsafe`)

The hook will warn you in real-time before insecure code is written.

## Supported Stacks

The skill auto-detects your project's technology stack:

| Framework | ORM | Language |
|-----------|-----|----------|
| NestJS | Prisma | TypeScript |
| Express | TypeORM | JavaScript |
| FastAPI | SQLAlchemy | Python |
| Django | Django ORM | Python |
| Spring Boot | JPA/Hibernate | Java |
| Rails | ActiveRecord | Ruby |
| Gin/Echo | GORM | Go |

## Compliance Frameworks

| Framework | Coverage |
|-----------|----------|
| HIPAA Security Rule | PHI detection, audit trails, encryption |
| SOC 2 Type II | Access controls, monitoring, logging |
| OWASP Top 10 (2021) | All 10 categories |
| HITRUST CSF | 19 domains, 156+ controls |
| FDCPA / Reg F | Call restrictions, consent, DNC |
| TCPA | Automated communications compliance |
| FIPS 203/204/205 | Post-quantum cryptography |
