---
name: fdcpa-tcpa
description: Verify FDCPA and TCPA compliance for debt collection and automated communications
---

# FDCPA/TCPA Compliance (Opt-In)

Verify compliance with the Fair Debt Collection Practices Act (FDCPA), Regulation F, and the Telephone Consumer Protection Act (TCPA). Enable this module for projects that handle debt collection, automated calling, or consumer communications.

## When to Use

- Projects handling debt collection workflows
- Automated dialer or voice AI systems
- SMS/email campaign platforms targeting consumers
- Healthcare collections and patient billing

## FDCPA / Regulation F Checks

### 1. Call Time Restrictions
```
Rule: No calls before 8:00 AM or after 9:00 PM in the debtor's LOCAL time zone.
```

**Verify:**
- Time zone detection logic exists for each debtor
- Call scheduling respects local time boundaries
- Timezone edge cases handled (DST transitions, unknown timezone)

```regex
# Search for time restriction enforcement
(callWindow|allowedHours|restrictedHours|canCall|isCallable)
(before8am|after9pm|callTimeCheck|timezone.*check)
(localTime|debtorTimezone|recipientTimezone)
```

### 2. Call Frequency Caps
```
Rule: Maximum 7 calls per 7-day period per debtor per account.
```

**Verify:**
- Call counting logic per debtor account
- 7-day rolling window enforcement
- Counter resets properly

```regex
(callFrequency|callLimit|maxCalls|callCap|callCount)
(7.*day|seven.*day|weekly.*limit|frequency.*cap)
```

### 3. Mini-Miranda / Validation Notice
```
Rule: Within 5 days of first contact, send written validation notice with:
- Amount of debt
- Name of creditor
- Consumer's right to dispute within 30 days
```

**Verify:**
- Validation notice template exists
- Auto-triggered after first contact
- Contains all required disclosures

### 4. Do Not Call (DNC) Compliance
```
Rule: Honor cease-and-desist requests. Scrub against DNC lists.
```

**Verify:**
- DNC scrubbing before outbound calls
- Opt-out/revocation handling stops all automated contact
- DNC list integration (federal + state)

```regex
(doNotCall|DNC|dncList|dncScrub|dncCheck|optOut|ceaseDesist|revocation)
```

### 5. Third-Party Disclosure
```
Rule: Cannot disclose debt information to third parties (except spouse, parent of minor, guardian, attorney).
```

**Verify:**
- Third-party contact restrictions enforced
- Disclosure rules in call scripts / AI agent prompts

## TCPA Checks

### 6. Prior Express Written Consent
```
Rule: Automated calls/texts require prior express written consent.
```

**Verify:**
- Consent capture and storage mechanism
- Consent timestamp and method recorded
- Consent verification before automated contact

```regex
(consent|priorConsent|expressConsent|writtenConsent|consentRecord)
(consentDate|consentMethod|consentVerif)
```

### 7. Revocation Handling
```
Rule: Consumer can revoke consent at any time by any reasonable means.
```

**Verify:**
- Revocation processing logic exists
- All channels stopped after revocation (calls, SMS, email)
- Revocation recorded with timestamp

### 8. State-Specific Rules
Many states have additional restrictions beyond federal law:
- Different call time windows
- Stricter frequency limits
- Additional licensing requirements
- State DNC lists

```regex
(stateRules|stateRestrictions|stateLaw|stateCompliance)
(stateCallWindow|stateFrequency|stateLicense)
```

## Severity

| Finding | Severity |
|---------|----------|
| No call time restrictions | Critical |
| No frequency cap enforcement | Critical |
| Missing validation notice | High |
| No DNC scrubbing | Critical |
| No consent tracking | Critical |
| No revocation handling | High |
| Missing state-specific rules | Medium |

## Regulatory References

| Regulation | Citation | Requirement |
|-----------|----------|-------------|
| FDCPA | 15 USC 1692c(a) | Call time restrictions |
| Reg F | 12 CFR 1006.14(b) | 7-in-7 call frequency cap |
| Reg F | 12 CFR 1006.34 | Validation notice |
| TCPA | 47 USC 227(b) | Prior express consent |
| TCPA | 47 USC 227(c) | Do Not Call requirements |
