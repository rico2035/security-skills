---
name: secrets-audit
description: Detect hardcoded secrets, API keys, tokens, and credentials in source code and configuration
---

# Secrets & Configuration Audit

Detect hardcoded secrets, API keys, tokens, passwords, and credentials in source code, configuration files, and version control history.

## When to Use

- Before every commit (ideally as a pre-commit hook)
- During security audits and code reviews
- When onboarding new team members
- Before open-sourcing any code

## Search Patterns

### API Keys and Tokens
```regex
# Generic API key patterns
(api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]

# Cloud provider keys
(AKIA[0-9A-Z]{16})                        # AWS Access Key ID
(sk-[a-zA-Z0-9]{20,})                     # OpenAI / Stripe secret key
(pk_live_[a-zA-Z0-9]{20,})                # Stripe publishable key
(whsec_[a-zA-Z0-9]{20,})                  # Stripe webhook secret
(sk-or-[a-zA-Z0-9\-]{20,})               # OpenRouter key
(re_[a-zA-Z0-9]{20,})                     # Resend key
(phc_[a-zA-Z0-9]{20,})                    # PostHog key
(AC[a-z0-9]{32})                          # Twilio Account SID
(ghp_[a-zA-Z0-9]{36})                     # GitHub personal access token
(gho_[a-zA-Z0-9]{36})                     # GitHub OAuth token
(glpat-[a-zA-Z0-9\-]{20,})               # GitLab personal access token
(xoxb-|xoxp-|xapp-)                       # Slack tokens
(sk-ant-[a-zA-Z0-9\-]{20,})              # Anthropic key
```

### Passwords and Credentials
```regex
# Hardcoded passwords
(password|passwd|pwd|pass)\s*[:=]\s*['"][^'"]{4,}['"]

# Connection strings with credentials
(mongodb|postgres|mysql|redis):\/\/\w+:\w+@

# Bearer tokens
Bearer\s+[A-Za-z0-9\-._~+/]+=*
Authorization.*['"][^'"]{20,}['"]
```

### Private Keys
```regex
-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

### Environment Variable Names in Source
```regex
# Sensitive env vars that should never be hardcoded
(ANTHROPIC|OPENAI|STRIPE|TWILIO|DEEPGRAM|AZURE|SUPABASE|DATABASE)_(API_KEY|SECRET|TOKEN|PASSWORD|URL)
(SECRET_KEY|JWT_SECRET|ENCRYPTION_KEY|MASTER_KEY)
```

## Files to Check

### Must Scan
- All source code (`**/*.{ts,js,py,go,java,rb,rs,php}`)
- Configuration files (`**/*.{json,yaml,yml,toml,xml,ini,cfg}`)
- Docker files (`Dockerfile*`, `docker-compose*`)
- CI/CD pipelines (`.github/workflows/*`, `.gitlab-ci.yml`, `Jenkinsfile`)
- Scripts (`**/*.{sh,ps1,bat,cmd}`)

### Must NOT Contain Secrets
- `*.env.example` / `*.env.template` (should have placeholder values only)
- `README.md` and documentation (should use `xxx` or `your-key-here`)

### Check Git History
```bash
# Check if .env was ever committed
git log --all --full-history -- '*.env' '.env*'

# Check for secrets in git history (requires git-secrets or similar)
git log -p --all -S 'sk-' -- '*.ts' '*.js' '*.py'
git log -p --all -S 'password' -- '*.ts' '*.js' '*.py'
```

## .gitignore Verification

Ensure these patterns are in `.gitignore`:
```
.env
.env.*
.env.local
.env.production
*.pem
*.key
*.p12
*.pfx
credentials.json
service-account*.json
*-credentials.*
```

## Severity

| Finding | Severity |
|---------|----------|
| Active API key in source code | Critical |
| Private key in repository | Critical |
| Password in source code | Critical |
| Connection string with credentials | Critical |
| Secret in git history (current branch) | High |
| Secret in git history (old branch) | Medium |
| Missing .gitignore entry | Medium |
| Placeholder looks like real secret | Low |

## Remediation

1. **Immediately rotate** any exposed secret
2. Move secrets to environment variables
3. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler)
4. Add pre-commit hooks to prevent future exposure
5. If secret was in git history: consider the secret compromised and rotate it

```bash
# Install pre-commit secret detection
# Option 1: git-secrets (AWS)
git secrets --install
git secrets --register-aws

# Option 2: detect-secrets (Yelp)
pip install detect-secrets
detect-secrets scan > .secrets.baseline

# Option 3: gitleaks
gitleaks detect --source .
```
