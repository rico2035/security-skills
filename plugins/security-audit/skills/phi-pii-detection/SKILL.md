---
name: phi-pii-detection
description: Detect PHI/PII leaks in logs, errors, API responses, and source code for HIPAA compliance
---

# PHI/PII Leak Detection

Scan your codebase for Protected Health Information (PHI) and Personally Identifiable Information (PII) exposure — the #1 HIPAA violation vector.

## When to Use

- Before any deployment to production
- After adding new logging, error handling, or API endpoints
- During HIPAA compliance reviews
- When onboarding new developers to verify secure coding practices

## Sensitive Data Categories

### Critical (block deploy if found)
- Social Security Numbers (SSN)
- Passwords, API keys, tokens
- Credit card / bank account numbers
- Full medical record numbers

### High (fix within 7 days)
- Date of birth combined with patient name
- Diagnosis codes combined with patient identifiers
- Insurance member IDs with patient info
- Full addresses with health context

### Medium (fix within 30 days)
- Email addresses in logs
- Phone numbers in error messages
- Partial identifiers without context

## Search Patterns

### Logging Statements
```regex
# JavaScript/TypeScript
console\.(log|warn|error|info|debug)\(.*\b(patient|ssn|dob|diagnosis|creditCard|bankAccount|socialSecurity|dateOfBirth|insuranceId|memberId)\b
logger\.(info|warn|error|debug)\(.*\b(patient|ssn|dob|diagnosis|creditCard|bankAccount)\b

# Python
logging\.(info|warning|error|debug|critical)\(.*\b(patient|ssn|dob|diagnosis|credit_card|bank_account)\b
print\(.*\b(patient|ssn|dob|diagnosis)\b

# Go
log\.(Print|Printf|Println|Fatal|Panic)\(.*\b(patient|ssn|dob|diagnosis)\b

# Java
(logger|LOG)\.(info|warn|error|debug)\(.*\b(patient|ssn|dob|diagnosis)\b
System\.out\.print.*\b(patient|ssn|dob|diagnosis)\b
```

### Error Responses
```regex
# Sensitive data in thrown errors
throw new.*Error\(.*\b(patient|ssn|dob|diagnosis|insurance)\b
raise.*Exception\(.*\b(patient|ssn|dob|diagnosis)\b

# Sensitive data in API responses
res\.(json|send|status)\(.*\b(patientName|SSN|dateOfBirth)\b
return.*(Response|JsonResponse)\(.*\b(patient|ssn|dob)\b
```

### Hardcoded Test Data (non-test files)
```regex
# SSN patterns outside test files
\b\d{3}-\d{2}-\d{4}\b

# Real-looking medical record numbers
\bMRN[:\s]*\d{6,10}\b
```

## Scan Scope

**Include:**
- All backend source files
- All frontend source files
- Configuration files
- API route handlers, controllers, services

**Exclude:**
- `*.test.*`, `*.spec.*` (test files)
- `*fixture*`, `*mock*`, `*seed*` (test data)
- `*__tests__*`, `*__mocks__*` (test directories)
- `node_modules/`, `venv/`, `.venv/`, `vendor/`

## Remediation

### Instead of logging PHI:
```typescript
// BAD
logger.error('Payment failed', { patientName, ssn, dob });

// GOOD
logger.error('Payment failed', { accountId, errorCode, requestId });
```

### Instead of exposing PHI in errors:
```typescript
// BAD
throw new Error(`Patient ${patientName} not found`);

// GOOD
throw new NotFoundException(`Account ${accountId} not found`);
```

### Use audit service for PHI access:
```typescript
// Log PHI access through dedicated audit trail
auditService.log({
  eventType: 'PHI_ACCESS',
  userId: currentUser.id,
  resourceType: 'Patient',
  resourceId: patientId,
  action: 'READ',
});
```

## HIPAA References

| Section | Requirement |
|---------|-------------|
| 164.312(a)(1) | Access controls for ePHI |
| 164.312(b) | Audit controls |
| 164.312(c)(1) | Integrity controls |
| 164.312(e)(1) | Transmission security |
| 164.530(j) | Retention requirements (6 years) |
