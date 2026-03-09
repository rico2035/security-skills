---
name: pqc-crypto
description: Audit post-quantum cryptography implementation for FIPS 203/204/205 compliance
---

# PQC Cryptography Audit (Opt-In)

Verify post-quantum cryptography (PQC) implementation against FIPS 203, 204, and 205 standards. Enable this module when your project uses or plans to use quantum-resistant cryptographic algorithms.

## When to Use

- Projects implementing ML-KEM, ML-DSA, or SLH-DSA
- Preparing for NIST PQC migration deadlines
- Healthcare or financial services requiring long-term data protection
- Government/defense projects with FIPS requirements

## FIPS Standards

| Standard | Algorithm | Purpose |
|----------|-----------|---------|
| FIPS 203 | ML-KEM (Kyber) | Key Encapsulation Mechanism |
| FIPS 204 | ML-DSA (Dilithium) | Digital Signatures |
| FIPS 205 | SLH-DSA (SPHINCS+) | Stateless Hash-Based Signatures |

## What to Check

### 1. Algorithm Implementation
```regex
# PQC library usage
(liboqs|oqs|pqcrypto|crystals|kyber|dilithium|sphincs)
(ml-kem|ml-dsa|slh-dsa|ML_KEM|ML_DSA|SLH_DSA)
(@noble/post-quantum|liboqs-python|pqcrypto-rs)
```

### 2. Hybrid Mode Verification
PQC should be combined with classical algorithms for defense-in-depth:
- Key exchange: X25519 + ML-KEM-1024
- Signatures: Ed25519 + ML-DSA-65
- Verify both classical and PQC results before accepting

### 3. Deprecated Algorithm Detection
```regex
# Must not use for new implementations
(RSA-1024|RSA-2048.*new|DES|3DES|RC4|RC2|MD5.*sign|SHA-1.*sign)
(Blowfish|CAST5|IDEA)
createCipher\('des|createCipher\('rc4
```

### 4. Key Management
- Key rotation policy exists and is automated
- Keys are stored in a Key Management Service (KMS), not in code
- Key sizes meet minimum requirements:
  - ML-KEM: 768 (Level 3) or 1024 (Level 5)
  - ML-DSA: 44 (Level 2), 65 (Level 3), or 87 (Level 5)
  - SLH-DSA: appropriate security level for use case

### 5. Fallback Path
- Verify graceful fallback to classical crypto (AES-256-GCM, Ed25519)
- Fallback triggers when PQC libraries are unavailable
- Both paths are tested

### 6. Crypto Agility
- Algorithm selection is configurable, not hardcoded
- Migration path documented for future algorithm changes
- Version/algorithm metadata stored alongside encrypted data

## Severity

| Finding | Severity |
|---------|----------|
| Deprecated algorithm in active use | High |
| PQC without hybrid mode | Medium |
| No fallback path for PQC failure | High |
| Key stored in source code | Critical |
| No key rotation policy | Medium |
| Missing crypto agility | Low |

## NIST Migration Timeline

| Phase | Deadline | Action |
|-------|----------|--------|
| Inventory | Now | Catalog all cryptographic usage |
| Plan | 2025-2026 | Select PQC algorithms, design hybrid mode |
| Migrate | 2026-2030 | Implement PQC, test, deploy |
| Deprecate | 2030-2035 | Remove standalone classical crypto |
