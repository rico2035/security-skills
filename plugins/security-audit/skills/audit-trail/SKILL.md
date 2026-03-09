---
name: audit-trail
description: Verify audit trail completeness for security events, data access, and compliance requirements
---

# Audit Trail Completeness

Verify that all security-relevant events, data access operations, and administrative actions are properly logged with sufficient detail for compliance and forensics.

## When to Use

- During HIPAA, SOC 2, or HITRUST compliance audits
- After adding new services that handle sensitive data
- When reviewing incident response readiness
- Before enterprise customer onboarding

## What Must Be Logged

### Critical Events (must log — compliance requirement)
| Event | Required Fields |
|-------|----------------|
| Login success/failure | userId, timestamp, IP, userAgent, method |
| Permission denied | userId, resource, action, reason |
| PHI/PII access | userId, tenantId, resourceType, resourceId, action |
| Data export/download | userId, dataType, recordCount, format |
| User creation/deletion | adminId, targetUserId, action |
| Role/permission changes | adminId, targetUserId, oldRole, newRole |
| Configuration changes | adminId, setting, oldValue, newValue |
| Payment transactions | userId, amount, status, method |
| API key creation/revocation | adminId, keyId, action |

### Important Events (should log)
| Event | Required Fields |
|-------|----------------|
| Password change/reset | userId, method, timestamp |
| MFA enable/disable | userId, method, timestamp |
| Session creation/termination | userId, sessionId, reason |
| File upload/deletion | userId, fileName, size, action |
| Bulk operations | userId, operation, recordCount |

## How to Verify

### 1. Find the Audit Service
```regex
# Search for audit service/module
class.*Audit(Service|Logger|Tracker|Module)
def.*(audit_log|log_audit|track_event|log_action|record_event)
function.*(auditLog|logAudit|trackEvent|logAction)
```

### 2. Check Coverage
```regex
# Find all services/modules that handle sensitive resources
class.*(Account|Patient|User|Payment|Claim|Invoice)Service
class.*(Account|Patient|User|Payment|Claim|Invoice)Controller

# For each, verify they import and use the audit service
import.*[Aa]udit|from.*audit|require.*audit
```

### 3. Verify Event Structure
Each audit event should include at minimum:
```typescript
interface AuditEvent {
  timestamp: string;       // ISO 8601
  eventType: string;       // 'PHI_ACCESS', 'LOGIN', 'PERMISSION_CHANGE'
  userId: string;          // Who performed the action
  tenantId?: string;       // Which tenant (multi-tenant)
  action: string;          // 'CREATE', 'READ', 'UPDATE', 'DELETE'
  resourceType: string;    // 'Patient', 'Account', 'Payment'
  resourceId: string;      // ID of the affected resource
  ipAddress?: string;      // Client IP
  userAgent?: string;      // Client user agent
  metadata?: object;       // Additional context (never PHI)
}
```

### 4. Verify Retention
- HIPAA: 6 years minimum
- SOC 2: per policy (typically 1-3 years)
- HITRUST: 6 years
- Check: is retention policy configured in the logging/storage system?

## Severity

| Finding | Severity |
|---------|----------|
| No audit service exists | Critical |
| PHI access not logged | Critical |
| Auth events not logged | High |
| Admin actions not logged | High |
| Missing required fields in events | Medium |
| No retention policy configured | Medium |
| Service handles sensitive data without audit logging | High |

## Compliance References

| Framework | Section | Requirement |
|-----------|---------|-------------|
| HIPAA | 164.312(b) | Audit controls |
| HIPAA | 164.530(j) | 6-year retention |
| SOC 2 | CC7.2 | Monitor system components for anomalies |
| SOC 2 | CC7.3 | Evaluate security events |
| HITRUST | 8.1 | Operational procedures and responsibilities |
| HITRUST | 11.1 | Reporting information security events |
