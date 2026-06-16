# PQC Standards

## Purpose

Defines approved post-quantum cryptography standards for QGuard Helix.

All PQC implementations must align with current NIST standards and approved migration practices.

---

# Approved NIST Standards

## FIPS 203

ML-KEM

Purpose:

Key Encapsulation Mechanism

Use Cases:

- TLS Hybrid Key Exchange
- VPN Key Establishment
- Secure Channels
- Machine-to-Machine Encryption

Recommended:

ML-KEM-768

Security Category 3

---

## FIPS 204

ML-DSA

Purpose:

Digital Signatures

Use Cases:

- Certificates
- Code Signing
- Identity Verification
- Document Signing

Recommended:

ML-DSA-65

Security Category 3

---

## FIPS 205

SLH-DSA

Purpose:

Stateless Hash-Based Signatures

Use Cases:

- Root CA
- Long-Term Signatures
- High Assurance Environments

---

# Hybrid Cryptography

Required During Migration

Approved Hybrids:

X25519 + ML-KEM-768

P-384 + ML-KEM-768

Ed25519 + ML-DSA-65

ECDSA P-384 + ML-DSA-65

---

# Approved Symmetric Algorithms

AES-256-GCM

ChaCha20-Poly1305

---

# Approved Hash Functions

SHA3-256

SHA3-512

SHAKE256

---

# Approved KDF

HKDF-SHA3-256

---

# Deprecated Algorithms

Flag as Quantum Vulnerable

- RSA-1024
- RSA-2048
- RSA-3072
- DSA
- DH
- ECDH
- ECDSA
- Ed25519 (standalone)

Note:

Classical algorithms remain acceptable only within approved hybrid deployments.

---

# PQC Readiness Assessment

Required Checks

- Certificate Inventory
- Algorithm Discovery
- Trust Mapping
- Dependency Mapping
- Hybrid Capability
- Vendor Readiness
- Crypto Agility

---

# Migration Principles

1. Discover First

2. Assess Dependencies

3. Simulate Changes

4. Deploy Hybrid

5. Validate

6. Monitor

7. Transition

8. Optimize

---

# Compliance References

- NIST FIPS 203
- NIST FIPS 204
- NIST FIPS 205
- NIST SP 800-208
- NIST SP 800-57
- NIST SP 800-131A
- NSA CNSA 2.0