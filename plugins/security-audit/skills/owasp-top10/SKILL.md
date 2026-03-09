---
name: owasp-top10
description: Scan codebase for OWASP Top 10 (2021) web application vulnerabilities
---

# OWASP Top 10 Scan

Scan the codebase for the OWASP Top 10 (2021 edition) most critical web application security risks.

## When to Use

- Before every production deployment
- During code reviews touching auth, data access, or user input handling
- As part of periodic security audits
- When preparing for penetration testing

## A01: Broken Access Control

**Risk:** Users acting beyond their intended permissions.

```regex
# Missing auth decorators/guards on endpoints
@(Get|Post|Put|Delete|Patch)\(
# Cross-reference: each must have @UseGuards or @Public

# Endpoints marked public that shouldn't be
@Public|@AllowAnonymous|@SkipAuth|@no_auth_required

# Direct object reference without ownership check
params\.id|req\.params\.\w+Id
# Verify: does the handler check ownership before returning data?
```

## A02: Cryptographic Failures

**Risk:** Weak or missing encryption for sensitive data.

```regex
# Weak hash algorithms
(md5|sha1|createHash\('md5'|createHash\('sha1'|hashlib\.md5|hashlib\.sha1)

# Hardcoded secrets
(password|secret|api_key|apiKey|token|credential)\s*[:=]\s*['"][^'"]{8,}['"]

# Weak encryption
(DES|3DES|RC4|RC2|Blowfish)
createCipher\(|createCipheriv\('des|createCipheriv\('rc4
```

## A03: Injection

**Risk:** Untrusted data sent as part of a command or query.

```regex
# Code injection
eval\(|new Function\(|exec\(|execSync\(
subprocess\.call\(.*shell=True|os\.system\(|os\.popen\(

# SQL injection
\$queryRawUnsafe|\$executeRawUnsafe
\.raw\(.*\$\{|\.raw\(.*%s|\.raw\(.*\+\s*
f".*SELECT.*FROM|f".*INSERT.*INTO|f".*UPDATE.*SET|f".*DELETE.*FROM

# XSS
\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\(
v-html=|ng-bind-html=|\{\{.*\|.*safe\}\}

# Command injection
child_process|spawn\(.*\$\{|exec\(.*\$\{
```

## A04: Insecure Design

**Risk:** Missing or ineffective security controls by design.

```regex
# Missing rate limiting
# Check: do auth endpoints have rate limiting?
@(Post|Put)\(.*login|@(Post|Put)\(.*register|@(Post|Put)\(.*reset

# Missing CSRF protection
# Check: does the framework have CSRF middleware enabled?
csrf|csrfProtection|@csrf_protect
```

## A05: Security Misconfiguration

**Risk:** Insecure default configurations, unnecessary features enabled.

```regex
# Permissive CORS
origin:\s*['"]\*['"]|Access-Control-Allow-Origin.*\*|cors\(\)(?!.*origin)

# Debug mode in production
DEBUG\s*=\s*True|NODE_ENV.*development
app\.debug\s*=\s*True

# Exposed stack traces
stackTrace|stack.*trace|err\.stack
```

## A06: Vulnerable and Outdated Components

**Action:** Run dependency audit.

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

## A07: Identification and Authentication Failures

**Risk:** Weak authentication mechanisms.

```regex
# Hardcoded credentials
(username|user)\s*[:=]\s*['"]admin['"]
(password|pass|pwd)\s*[:=]\s*['"][^'"]+['"]

# Missing MFA enforcement
mfa|twoFactor|2fa|multi.factor
# Check: is MFA enforced for admin/privileged roles?

# Weak session configuration
(maxAge|expires).*(\d{8,}|365d|30d)
# Check: are session durations reasonable?
```

## A08: Software and Data Integrity Failures

**Risk:** Code and infrastructure without integrity verification.

```regex
# Missing input validation
# Check: do endpoints use Zod, class-validator, Pydantic, or similar?
@Body\(\)|req\.body|request\.json|request\.data
# Cross-reference: is a validation schema/pipe applied?

# Insecure deserialization
(pickle\.loads|yaml\.load\((?!.*Loader)|unserialize\(|ObjectInputStream)
```

## A09: Security Logging and Monitoring Failures

**Risk:** Insufficient logging of security-relevant events.

```regex
# Check: are these events logged?
# - Failed login attempts
# - Access denied events
# - Data access (especially PHI/PII)
# - Admin actions
# - Configuration changes

# Search for audit/logging service usage
audit|AuditService|audit_log|security_log|EventLog
```

## A10: Server-Side Request Forgery (SSRF)

**Risk:** Server-side requests to user-controlled URLs.

```regex
# User input flowing into server-side requests
fetch\(.*\$\{|fetch\(.*req\.|fetch\(.*request\.
axios\.\w+\(.*\$\{|axios\.\w+\(.*req\.
requests\.(get|post|put|delete)\(.*f"|requests\.\w+\(.*\+
http\.Get\(.*\+|http\.Post\(.*\+
urllib\.request\.urlopen\(

# Unvalidated redirects
res\.redirect\(.*req\.|redirect\(.*request\.
Location.*\$\{|Location.*req\.
```

## Severity Map

| Category | Default Severity |
|----------|-----------------|
| A01 Broken Access Control | Critical |
| A02 Cryptographic Failures | High |
| A03 Injection | Critical |
| A04 Insecure Design | Medium |
| A05 Security Misconfiguration | Medium |
| A06 Vulnerable Components | High (depends on CVE) |
| A07 Auth Failures | High |
| A08 Data Integrity | Medium |
| A09 Logging Failures | Medium |
| A10 SSRF | High |
