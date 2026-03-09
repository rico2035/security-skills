---
name: tenant-isolation
description: Verify multi-tenant data segregation across all database queries and API endpoints
---

# Tenant Isolation Verification

Verify that multi-tenant data segregation is enforced across all database queries, API endpoints, and data access patterns. A tenant isolation failure is a critical security vulnerability that can expose one customer's data to another.

## When to Use

- After adding new database queries or services
- When reviewing pull requests that touch data access
- During SOC 2 or HIPAA compliance audits
- Before onboarding enterprise customers

## What to Check

### 1. Query-Level Isolation

Every database query in service/repository files must filter by tenant identifier.

**Prisma:**
```regex
# Find queries — each must include tenantId or organizationId
prisma\.\w+\.(findMany|findFirst|findUnique|update|delete|count|aggregate|groupBy)\(

# Dangerous: raw queries without tenant filtering
\$queryRaw|\$executeRaw|\$queryRawUnsafe
```

**TypeORM:**
```regex
# Find queries
\.(find|findOne|findOneBy|createQueryBuilder|getRepository)\(

# Check for tenant where clause
\.where\(.*tenant
```

**SQLAlchemy:**
```regex
session\.(query|execute)\(
\.filter\(.*tenant
```

**Django ORM:**
```regex
\.objects\.(filter|get|all|exclude|create|update|delete)\(
# Must include tenant/organization filter
```

**Raw SQL (any framework):**
```regex
# All raw SQL must have tenant_id in WHERE
(SELECT|UPDATE|DELETE|INSERT).*FROM
# Verify WHERE tenant_id = ? or equivalent
```

### 2. Middleware/Guard Enforcement

```regex
# Check that tenant guard/middleware exists and is applied
@UseGuards.*Tenant|TenantGuard|TenantMiddleware|tenant_required
@tenant_scope|@require_tenant|@multi_tenant

# Controllers without tenant protection
@Controller.*(?!.*@UseGuards.*Tenant)
```

### 3. Cross-Tenant Data Leaks

Check for:
- Joins/includes that don't respect tenant boundaries
- Cached data without tenant-scoped cache keys
- Background jobs that process data without tenant context
- WebSocket connections that broadcast across tenants
- File uploads/downloads without tenant-scoped paths

## Severity

| Finding | Severity |
|---------|----------|
| Query missing tenant filter | Critical |
| Raw SQL without tenant filter | Critical |
| Missing tenant guard on controller | High |
| Cross-tenant join without filter | Critical |
| Cache without tenant-scoped key | High |
| Background job without tenant context | High |

## Remediation

### Always include tenant in queries:
```typescript
// BAD
const accounts = await prisma.account.findMany({
  where: { status: 'ACTIVE' },
});

// GOOD
const accounts = await prisma.account.findMany({
  where: { tenantId, status: 'ACTIVE' },
});
```

### Use Row-Level Security (RLS):
```sql
CREATE POLICY tenant_isolation ON accounts
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

### Apply tenant guard globally:
```typescript
// NestJS — apply to all routes
@UseGuards(TenantGuard)
@Controller('accounts')
export class AccountsController { ... }
```

## SOC 2 References

| Control | Requirement |
|---------|-------------|
| CC6.1 | Logical access security |
| CC6.3 | Role-based access controls |
| CC6.7 | Restrict access to confidential information |
