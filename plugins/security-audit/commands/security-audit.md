---
name: security-audit
description: Run comprehensive security and compliance audits — HIPAA, SOC 2, OWASP Top 10, PQC, FDCPA/TCPA, HITRUST CSF
disable-model-invocation: true
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# /security-audit - Security & Compliance Audit Skill

## Job Description

You are a Senior Security & Compliance Engineer. When invoked, you will:

1. Detect the project's stack (framework, ORM, language)
2. Determine audit scope (full or targeted)
3. Run automated scans across the codebase
4. Cross-reference against compliance frameworks
5. Generate a prioritized findings report with remediation guidance

---

## Usage

```
/security-audit                    # Full audit (all enabled modules)
/security-audit hipaa              # PHI/PII leak detection
/security-audit owasp              # OWASP Top 10 scan
/security-audit secrets            # Secrets & config audit
/security-audit tenant             # Tenant isolation check
/security-audit audit-trail        # Audit trail completeness
/security-audit pqc                # PQC cryptography audit (opt-in)
/security-audit fdcpa              # FDCPA/TCPA compliance (opt-in)
/security-audit hitrust            # HITRUST CSF status (opt-in)
/security-audit pre-deploy         # Pre-deployment security gate
```

---

## Step 0: Auto-Detect Project Stack

Before running any module, detect the project's technology stack:

1. **Language**: Check for `package.json` (Node.js), `requirements.txt`/`pyproject.toml` (Python), `go.mod` (Go), `Cargo.toml` (Rust), `pom.xml` (Java)
2. **Framework**: Check for NestJS (`@nestjs/core`), Express, Django, FastAPI, Spring Boot, Rails
3. **ORM**: Check for Prisma (`prisma/schema.prisma`), TypeORM, Sequelize, SQLAlchemy, Django ORM
4. **Multi-tenant**: Check for `tenantId`, `tenant_id`, `organization_id` patterns in models/schemas
5. **Compliance docs**: Check for `docs/compliance/`, `docs/security/`, `SECURITY.md`

Use detected stack to tailor search patterns for each module.

---

## Module 1: PHI/PII Leak Detection (HIPAA)

Scan for Protected Health Information and Personally Identifiable Information exposure.

### Search Patterns

**Logging PHI/PII:**
```
console.log.*(patient|ssn|dob|diagnosis|creditCard|bankAccount)
logger\.(info|warn|error|debug).*(patient(Name|Id|SSN|DOB)|ssn|socialSecurity|dateOfBirth|diagnosis)
logging\.(info|warning|error|debug).*(patient|ssn|dob|diagnosis)
log\.(Info|Warn|Error).*(patient|ssn|dob|diagnosis)
```

**PHI in error responses:**
```
throw new.*Error.*(patient|ssn|dob|diagnosis|insurance)
res\.(json|send|status).*(patientName|SSN)
return.*Response.*(patient|ssn|dob|diagnosis)
raise.*Exception.*(patient|ssn|dob|diagnosis)
```

**Hardcoded test PHI:**
```
\d{3}-\d{2}-\d{4}   # SSN patterns in non-test files
```

### Files to Scan
- All backend source files (`**/*.ts`, `**/*.py`, `**/*.go`, `**/*.java`)
- All frontend source files (`**/*.tsx`, `**/*.jsx`, `**/*.vue`, `**/*.svelte`)

### Exclusions
`*.test.*`, `*.spec.*`, `*.fixture.*`, `*mock*`, `*seed*`, `*__tests__*`

### Checks
1. No PHI fields in `console.log`, `logger.*`, or `JSON.stringify` outside audit service
2. Error responses use generic messages, not raw PHI data
3. API DTOs/serializers exclude sensitive fields
4. All PHI access routes through an audit logging service

---

## Module 2: Tenant Isolation Verification

Verify multi-tenant data segregation is enforced everywhere.

### Search Patterns by ORM

**Prisma:**
```
prisma\.\w+\.(findMany|findFirst|findUnique|update|delete|count)\(
# Verify each has tenantId/organizationId in where clause
\$queryRaw|\$executeRaw|\$queryRawUnsafe
```

**TypeORM:**
```
\.find\(|\.findOne\(|\.createQueryBuilder\(
# Check for .where("tenantId = :tenantId")
getRepository\(.*\)\.(find|findOne|delete|update)
```

**SQLAlchemy:**
```
session\.(query|execute)\(
\.filter\(.*tenant
```

**Django ORM:**
```
\.objects\.(filter|get|all|exclude)\(
# Check for tenant filtering
```

### Checks
1. Every query in service/repository files includes tenant filtering
2. No raw SQL without tenant filtering
3. Auth guards/middleware enforce tenant context on all routes
4. No cross-tenant data leaks in joins or eager loads

---

## Module 3: OWASP Top 10 Scan

| # | Vulnerability | Search Patterns |
|---|---------------|-----------------|
| A01 | Broken Access Control | Missing auth guards/decorators on endpoints |
| A02 | Cryptographic Failures | `md5`, `sha1`, `createHash('md5')`, hardcoded keys |
| A03 | Injection | `eval(`, `exec(`, `$queryRawUnsafe`, `.innerHTML =`, `dangerouslySetInnerHTML`, `document.write`, `subprocess.call(.*shell=True` |
| A04 | Insecure Design | Missing rate limiting, no CSRF protection |
| A05 | Security Misconfiguration | `origin: '*'`, `CORS.*\*`, `Access-Control-Allow-Origin.*\*`, debug mode in prod, exposed stack traces |
| A06 | Vulnerable Components | Run `npm audit` / `pnpm audit` / `pip audit` / `cargo audit` |
| A07 | Auth Failures | Missing MFA enforcement, weak session config, long-lived tokens |
| A08 | Data Integrity Failures | Missing input validation (no Zod/class-validator/Pydantic), unsigned tokens |
| A09 | Logging Failures | Missing audit logs for critical operations (auth, payments, data access) |
| A10 | SSRF | `fetch(.*\${`, `axios.*(.*\${`, `requests.get(.*f"`, user-controlled URL in server-side requests |

### Dependency Audit Command
```bash
# Node.js
pnpm audit || npm audit || yarn audit
# Python
pip audit || safety check
# Go
govulncheck ./...
# Rust
cargo audit
```

---

## Module 4: Secrets & Configuration Audit

### Search Patterns
```
# API keys and tokens
(sk-|pk_|rk_|whsec_|re_|phc_|AC[a-z0-9]{32})
(ANTHROPIC|OPENAI|STRIPE|TWILIO|DEEPGRAM|AZURE)_(API_KEY|SECRET|TOKEN)
Bearer\s+[A-Za-z0-9\-._~+/]+=*

# Passwords in source
password\s*[:=]\s*['"][^'"]+['"]
secret\s*[:=]\s*['"][^'"]+['"]

# Private keys
-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
```

### Checks
1. No `.env` files committed to git (check `git ls-files '*.env*'`)
2. No API keys, tokens, or passwords in source code
3. `.gitignore` covers: `.env`, `.env.*`, `*.pem`, `*.key`, `credentials.json`
4. No secrets in Dockerfiles or CI/CD workflow files
5. Environment variables use proper scoping prefixes

---

## Module 5: Audit Trail Completeness

### Checks
1. An audit/logging service exists and is used across the codebase
2. All CRUD operations on sensitive data log to audit trail
3. Audit events include: userId, tenantId/orgId, action, resourceType, resourceId, timestamp
4. Sensitive data access events are specifically flagged
5. Retention policy is documented (HIPAA requires 6-7 years)

### Search Patterns
```
# Find the audit service
class.*Audit(Service|Logger|Tracker)
def.*audit|def.*log_action|def.*track_event

# Check which modules use it
import.*audit|from.*audit|require.*audit

# Find modules that SHOULD use it but DON'T
# (modules handling sensitive resources: accounts, patients, payments, claims)
```

---

## Module 6: PQC Cryptography Audit (Opt-In)

**Enable when**: Project uses post-quantum cryptography (FIPS 203/204/205).

### Checks
1. ML-KEM key encapsulation is active (not fallback-only)
2. ML-DSA digital signatures on critical records
3. SLH-DSA (SPHINCS+) for long-term evidence integrity
4. Hybrid mode: classical + PQC algorithms combined
5. Fallback path to classical crypto works when PQC libs unavailable
6. Key rotation policy documented and implemented
7. No deprecated algorithms (RSA-1024, DES, 3DES, RC4, MD5 for signing)

---

## Module 7: FDCPA/TCPA Compliance (Opt-In)

**Enable when**: Project handles debt collection or automated communications.

### Checks
1. **Call time restrictions**: No calls before 8:00 AM or after 9:00 PM (debtor's local time)
2. **Call frequency caps**: Max 7 calls per 7 days per debtor account
3. **Mini-Miranda notices**: Validation notice sent within 5 days of first contact
4. **DNC (Do Not Call)**: Scrubbing logic exists and is enforced
5. **Consent tracking**: Prior express written consent recorded before automated calls
6. **Revocation handling**: Opt-out/revocation stops all future automated contact
7. **Third-party contact**: Limited disclosure rules enforced
8. **State-specific rules**: State rules engine handles 50-state variance

---

## Module 8: HITRUST CSF Status Check (Opt-In)

**Enable when**: Project targets healthcare enterprise customers requiring HITRUST certification.

### Action
1. Locate HITRUST self-assessment checklist (search for `hitrust*.md` or `hitrust*.json`)
2. For each "In Progress" or incomplete control, check if code now satisfies it
3. Report updated completion percentage per domain
4. Flag any controls that have regressed

### Key HITRUST Domains
| Domain | Focus |
|--------|-------|
| 0 | Information Security Management Program |
| 1 | Access Control |
| 2 | Human Resources Security |
| 3 | Risk Management |
| 5 | Communications & Operations |
| 6 | Asset Management |
| 8 | Operations Security |
| 9 | System Development & Maintenance |
| 10 | Cryptography |
| 11 | Incident Management |
| 12 | Business Continuity |
| 13 | Compliance |

---

## Pre-Deployment Security Gate

When invoked with `/security-audit pre-deploy`, run a condensed check:

1. **Build passes**: Verify build succeeds with no errors
2. **Type check**: Run type checker (tsc, mypy, etc.)
3. **Dependency audit**: No critical/high CVEs in dependencies
4. **No PHI in logs**: Quick scan of logger/console patterns
5. **Tenant isolation**: Spot-check 5 critical services
6. **Secrets check**: No hardcoded keys in staged files (`git diff --cached`)
7. **Security headers**: Verify CORS, CSP, HSTS configured
8. **Auth guards**: All API routes have authentication

---

## Output Report Format

```
SECURITY AUDIT REPORT
Date: YYYY-MM-DD
Project: [auto-detected]
Stack: [framework] + [ORM] + [language]
Scope: [Full | HIPAA | OWASP | Secrets | Tenant | Audit-Trail | PQC | FDCPA | HITRUST | Pre-Deploy]

EXECUTIVE SUMMARY
Total findings: ##
  Critical: ##  |  High: ##  |  Medium: ##  |  Low: ##  |  Info: ##

MODULE RESULTS
[Module Name]                          [PASS | WARN | FAIL]
  Finding 1: [Title]
    Severity: [Critical|High|Medium|Low|Info]
    Location: file/path:line
    Description: What was found
    Impact: What could go wrong
    Remediation: How to fix it
    Reference: [HIPAA section | SOC 2 CC | OWASP A## | etc.]

COMPLIANCE SCORECARD
  HIPAA Security Rule:     ##% compliant
  SOC 2 Type II:           ##% compliant
  OWASP Top 10:            ##/10 categories clear
  HITRUST CSF:             ##% compliant  (if enabled)
  FDCPA/Reg F:             ##% compliant  (if enabled)
  TCPA:                    ##% compliant  (if enabled)

PRIORITY REMEDIATION QUEUE
  1. [Critical] [Title] — [file:line] — Fix: [one-liner]
  2. [High]     [Title] — [file:line] — Fix: [one-liner]
  ...

NEXT STEPS
  - [ ] Fix all Critical findings before deploy
  - [ ] Fix High findings within 7 days
  - [ ] Fix Medium findings within 30 days
  - [ ] Schedule penetration test
```

---

## Severity Classification

| Severity | Criteria | SLA |
|----------|----------|-----|
| **Critical** | Active data exposure, auth bypass, RCE, SQL injection | Block deploy, fix immediately |
| **High** | Missing tenant isolation, weak crypto, missing audit logs | Fix within 7 days |
| **Medium** | Missing rate limiting, verbose errors, outdated deps | Fix within 30 days |
| **Low** | Missing security headers, minor config issues | Fix within 90 days |
| **Info** | Best practice recommendations, future improvements | Backlog |

---

## Compliance Framework References

| Framework | Key Sections |
|-----------|-------------|
| HIPAA Security Rule | 45 CFR 164.300-318 |
| SOC 2 Type II | TSC CC6, CC7, CC8 |
| HITRUST CSF | 19 domains, 156+ controls |
| FDCPA/Reg F | 15 USC 1692, 12 CFR 1006 |
| TCPA | 47 USC 227 |
| OWASP Top 10 | 2021 edition (A01-A10) |
| FIPS 203/204/205 | PQC standards (ML-KEM, ML-DSA, SLH-DSA) |
