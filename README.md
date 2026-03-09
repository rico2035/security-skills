# Security Skills - Security & Compliance Audit Toolkit for Claude Code

> **A comprehensive security and compliance audit plugin for Claude Code. Scans your codebase for vulnerabilities, PHI/PII leaks, hardcoded secrets, tenant isolation failures, and compliance gaps across HIPAA, SOC 2, OWASP, HITRUST, FDCPA/TCPA, and PQC standards.**

Security Skills brings automated security auditing directly into your AI-assisted development workflow. Catch vulnerabilities before they ship, not after.

---

## What is Security Skills?

Security Skills is a **Claude Code plugin** that provides on-demand security and compliance audits for any codebase. It provides:

| Feature | Description |
|---------|-------------|
| **PHI/PII Detection** | Find sensitive data exposure in logs, errors, and API responses |
| **OWASP Top 10** | Scan for all 10 critical web application vulnerabilities |
| **Secrets Scanning** | Detect hardcoded API keys, passwords, and private keys |
| **Tenant Isolation** | Verify multi-tenant data segregation across all queries |
| **Audit Trail** | Check completeness of security event logging |
| **Compliance Scoring** | Scorecard across HIPAA, SOC 2, HITRUST, FDCPA/TCPA |
| **Real-Time Hooks** | Catch insecure code as it's written, not after |
| **Stack Auto-Detection** | Tailors patterns to your framework, ORM, and language |

---

## Quick Start

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

---

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

---

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

---

## Stack Auto-Detection

The skill auto-detects your project's technology stack and tailors search patterns accordingly:

- **Languages:** TypeScript, JavaScript, Python, Go, Java, Ruby, Rust
- **Frameworks:** NestJS, Express, FastAPI, Django, Spring Boot, Rails
- **ORMs:** Prisma, TypeORM, Sequelize, SQLAlchemy, Django ORM

---

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

---

## Report Format

The audit produces a structured report with:
- Executive summary (finding counts by severity)
- Per-module results (PASS / WARN / FAIL)
- Compliance scorecard (% compliant per framework)
- Priority remediation queue (ordered by severity)
- Actionable fix guidance with file locations

### Severity Levels

| Severity | Criteria | SLA |
|----------|----------|-----|
| **Critical** | Active data exposure, auth bypass, RCE, SQL injection | Block deploy, fix immediately |
| **High** | Missing tenant isolation, weak crypto, missing audit logs | Fix within 7 days |
| **Medium** | Missing rate limiting, verbose errors, outdated deps | Fix within 30 days |
| **Low** | Missing security headers, minor config issues | Fix within 90 days |
| **Info** | Best practice recommendations | Backlog |

---

## Real-Time Hooks

When installed as a plugin, a `PreToolUse` hook runs on every `Edit` and `Write` operation, catching:
- PHI/PII in logging statements
- Hardcoded secrets and API keys
- Injection-prone patterns (`eval`, `innerHTML`, `$queryRawUnsafe`)

---

## Directory Structure

```
security-skills/
├── .claude-plugin/
│   └── marketplace.json                  # Plugin marketplace manifest
├── plugins/
│   └── security-audit/
│       ├── .claude-plugin/
│       │   └── plugin.json               # Plugin metadata
│       ├── commands/
│       │   └── security-audit.md         # /security-audit slash command
│       ├── skills/
│       │   ├── phi-pii-detection/        # HIPAA PHI/PII scanning
│       │   ├── tenant-isolation/         # Multi-tenant verification
│       │   ├── owasp-top10/              # OWASP Top 10 (A01-A10)
│       │   ├── secrets-audit/            # API keys, passwords, private keys
│       │   ├── audit-trail/              # Audit logging completeness
│       │   ├── pqc-crypto/               # FIPS 203/204/205 (opt-in)
│       │   ├── fdcpa-tcpa/               # Debt collection rules (opt-in)
│       │   └── hitrust-csf/              # HITRUST 19-domain check (opt-in)
│       ├── hooks/
│       │   ├── hooks.json                # PreToolUse hook config
│       │   └── security_hook.py          # Real-time PHI/secrets detector
│       └── README.md
├── setup.sh                              # Unix install (submodule fallback)
├── setup.ps1                             # Windows install (submodule fallback)
├── package.json
├── LICENSE
└── README.md
```

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Author

**Ric S Kolluri** | [Novatar.ai](https://novatar.ai)

Security Skills was built for AI-assisted development workflows — designed for healthcare SaaS, fintech, and any team that needs compliance-grade security auditing baked into their development process.

---

## Credits

- Built for use with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and AI-assisted development tools
- Part of the [Novatar.ai](https://novatar.ai) development ecosystem
- Companion to [PRIME](https://github.com/rico2035/prime_master) — Progressive Release Implementation & Management Ecosystem

---

<p align="center">
  <strong>Ship secure code, every time.</strong>
  <br><br>
  Made with AI by <a href="https://novatar.ai">Novatar.ai</a>
</p>
