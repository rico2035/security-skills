# Security Audit Plugin

Security and compliance audit toolkit for Claude Code. Scans your codebase for vulnerabilities, compliance gaps, and security misconfigurations.

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

This plugin includes a `PreToolUse` hook that runs on `Edit`, `Write`, and `MultiEdit` operations.

It hard-blocks (permission denied) when real secret material is detected:

- API keys and tokens: `sk-`, `sk-ant-`, `AKIA`, `ghp_`, `gho_`, `glpat-`, Slack `xox` tokens, Stripe `whsec_`
- Private key blocks
- Connection strings with embedded credentials

It asks for your confirmation on risky patterns:

- Likely PHI/PII in logging statements
- Hardcoded passwords
- Injection-prone patterns: `eval`, `new Function`, `$queryRawUnsafe` / `$executeRawUnsafe`, `innerHTML` assignment, `dangerouslySetInnerHTML`, `document.write`, `subprocess` with `shell=True`, `os.system`

PHI and password checks are skipped for test, fixture, mock, and seed file paths. Secret checks apply everywhere.

The hook requires Python 3.9+ available as `python3` on PATH. If Python is missing, the hook reports an error but does not block your work.

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

## Feeding Foundri

The plugin can feed a Foundri console with machine-readable output. Three pieces, all optional:

### 1. JSON report emitter

`/security-audit` still prints the human-readable markdown report, and additionally writes a machine-readable report to `./.foundri/report.json` in the pinned `report_format_version: 1` contract. The contract lives in `schema/report.schema.json` with a full example in `schema/report.example.json` and a second fixture in `schema/report.fixture.json`. Evidence is always redacted — never live secrets, PHI, or PII.

### 2. Hook-event logger

Every hook decision (`block`, `ask`, `allow`) is appended as one JSON line to an append-only sink. Each line carries `id`, `decision`, `rule`, `tool`, `file_path`, `match` (a redacted descriptor, never the matched text), `actor` (git user email, else `"local"`), and `at` (ISO 8601 UTC). Logging fails open: an unwritable sink never blocks your edit.

### 3. Publisher

`tools/foundri-publish/foundri_publish.py` (Python 3.9+, stdlib only):

```bash
# Push a report to Foundri (validates against the v1 contract first)
python tools/foundri-publish/foundri_publish.py push .foundri/report.json

# Follow the hook-event sink and stream new events to Foundri
python tools/foundri-publish/foundri_publish.py tail --from-start
```

Both commands exit non-zero on validation or HTTP failure.

### Environment variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `FOUNDRI_HOOK_LOG` | hook logger, `tail` | Hook-event sink path. Default `~/.foundri/hook-events.jsonl` |
| `FOUNDRI_INGEST_URL` | `push` | Foundri ingest endpoint for reports |
| `FOUNDRI_EVENTS_URL` | `tail` | Foundri ingest endpoint for hook events |
| `FOUNDRI_TOKEN` | `push`, `tail` | Per-project bearer token |

### CI setup (GitHub Actions)

`.github/workflows/foundri-audit.yml` runs the audit in CI and publishes the report via the composite action in `.github/actions/foundri-publish/`. To enable it in your repo:

1. Add the `FOUNDRI_TOKEN` repo secret (per-project token from Foundri).
2. Add the `FOUNDRI_INGEST_URL` repo variable (your ingest endpoint).
3. Add an `ANTHROPIC_API_KEY` (or `CLAUDE_CODE_OAUTH_TOKEN`) repo secret so the audit step can run.
4. Push to `main` or trigger the `Foundri audit` workflow manually.

### Tests

```bash
# Hook logger unit tests (stdlib only)
python plugins/security-audit/hooks/test_security_hook.py

# Schema/example/fixture agreement (requires the jsonschema package)
python plugins/security-audit/schema/test_report_schema.py
```
