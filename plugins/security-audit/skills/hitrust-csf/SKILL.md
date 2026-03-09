---
name: hitrust-csf
description: Check HITRUST Common Security Framework compliance status across 19 domains
---

# HITRUST CSF Status Check (Opt-In)

Verify implementation status against the HITRUST Common Security Framework (CSF). Enable this module for healthcare projects targeting enterprise customers that require HITRUST certification.

## When to Use

- Preparing for HITRUST CSF assessment
- Enterprise healthcare customer due diligence
- Annual compliance recertification
- After major architecture changes

## How It Works

1. Search for an existing HITRUST self-assessment file (`hitrust*.md`, `hitrust*.json`, `hitrust*.csv`)
2. If found: parse each control's status and verify against codebase
3. If not found: run a baseline assessment across all 19 domains
4. Report completion percentage per domain and overall

## Key HITRUST Domains

### Domain 0: Information Security Management Program
**Check:**
- Security policy document exists
- Annual review schedule documented
- Security roles and responsibilities defined (RACI matrix)
- Risk management program established

### Domain 1: Access Control
**Check:**
```regex
# Authentication implementation
(OAuth|OIDC|OpenID|JWT|session|Clerk|Auth0|Cognito)
(MFA|twoFactor|2FA|multi.factor)

# RBAC implementation
(role|permission|guard|authorize|canAccess|hasPermission)
(Role\.(Admin|Owner|Member|Viewer)|UserRole|PermissionLevel)

# Row-level security / tenant isolation
(tenantId|organizationId|tenant_id|org_id)
(RLS|row.level.security|policy.*tenant)
```

### Domain 5: Communications and Operations Management
**Check:**
- Change management procedures documented
- Capacity management monitoring
- Separation of development/test/production environments
- Backup procedures configured

### Domain 8: Operations Security
**Check:**
```regex
# Input validation
(class-validator|Zod|Pydantic|joi|yup|express-validator)
(@IsString|@IsEmail|@IsNumber|@MinLength|z\.string|z\.number)

# Output encoding
(sanitize|escape|encode|DOMPurify|xss)

# Dependency management
(package-lock|pnpm-lock|yarn\.lock|Pipfile\.lock|poetry\.lock)
```

### Domain 9: System Development and Maintenance
**Check:**
- Secure SDLC documented
- Code review process (PR templates, review requirements)
- Security testing in CI/CD pipeline
- Vulnerability management process

### Domain 10: Cryptography
**Check:**
```regex
# Encryption at rest
(AES-256|AES_256|aes-256-gcm|encrypt|decrypt)

# Encryption in transit
(TLS|HTTPS|SSL|wss://)
(HSTS|Strict-Transport-Security)

# Key management
(KMS|keyManagement|keyRotation|key_rotation)
```

### Domain 11: Incident Management
**Check:**
- Incident response plan exists
- Breach notification procedures (HIPAA: 60 days)
- Security event monitoring
- Incident classification scheme

### Domain 12: Business Continuity
**Check:**
- Backup and recovery procedures
- RPO and RTO defined
- Disaster recovery plan
- Annual DR testing documented

### Domain 13: Compliance
**Check:**
- Regulatory requirements identified (HIPAA, SOC 2, etc.)
- Internal audit schedule
- External audit planning
- Compliance monitoring process

## Output Format

```
HITRUST CSF COMPLIANCE STATUS
Date: YYYY-MM-DD

Domain                                    Status      Score
----------------------------------------------------------
0  Info Security Management Program       Complete    100%
1  Access Control                         Complete     95%
2  Human Resources Security               Complete    100%
3  Risk Management                        In Progress  90%
5  Communications & Operations            Complete     95%
6  Asset Management                       Complete    100%
7  Physical & Environmental               N/A (Cloud) 100%
8  Operations Security                    Complete     95%
9  System Development & Maintenance       In Progress  85%
10 Cryptography                           Complete     90%
11 Incident Management                    Complete    100%
12 Business Continuity                    In Progress  80%
13 Compliance                            In Progress  85%
----------------------------------------------------------
OVERALL                                                93%

Controls Needing Attention:
  - 0.1.b: Annual policy review — schedule needed
  - 3.2.c: Risk treatment plans — documentation incomplete
  - 12.1.c: Business continuity testing — annual test due
  - 13.2.a: SOC 2 Type II audit — schedule for next quarter
```

## Severity

| Finding | Severity |
|---------|----------|
| Critical domain below 80% | High |
| Any domain below 50% | Critical |
| Regression from previous assessment | High |
| Missing incident response plan | Critical |
| No encryption at rest | Critical |
| Missing access controls | Critical |
