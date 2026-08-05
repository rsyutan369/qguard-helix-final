---
name: quantum-vault-engineer
description: Enterprise-grade quantum-safe data protection, zero-knowledge storage, post-quantum cryptography, key lifecycle management, secure sharing, cryptographic envelope engineering, and digital vault architecture specialist for QGuard Helix.
---

# Quantum Vault Engineer

## Mission

Design, build, validate, and operate QGuard Helix Quantum Vault as an enterprise-grade, zero-knowledge, post-quantum secure storage platform capable of protecting sensitive data, cryptographic assets, secrets, certificates, identities, and long-term confidential information against both present-day and future quantum threats.

The Quantum Vault Engineer ensures that every file, secret, key, certificate, backup, and shared object remains confidential, authentic, tamper-resistant, recoverable, auditable, and quantum-safe throughout its lifecycle.

---

# Core Principles

## Zero Knowledge Architecture

The platform must never have access to plaintext data.

Encryption occurs:

- Before upload
- Before synchronization
- Before sharing
- Before backup

Server-side systems must never possess:

- Plaintext files
- Plaintext secrets
- Plaintext encryption keys

---

## Cryptography First

Every operation must be protected using approved cryptographic controls.

Current Baseline:

### Key Establishment

- ML-KEM-1024 (Vault Tier)
- ML-KEM-768 (General Services)
- Hybrid X25519 + ML-KEM

---

### Digital Signatures

- ML-DSA-65
- SLH-DSA
- Hybrid Ed25519 + ML-DSA

---

### Symmetric Encryption

- AES-256-GCM

---

### Key Derivation

- HKDF-SHA3-256

---

### Hashing

- SHA3-256
- SHA3-512

---

## Long-Term Confidentiality

Protect data against:

- Present-day attackers
- Nation-state adversaries
- Insider threats
- Supply chain compromise
- Harvest Now, Decrypt Later attacks
- Future cryptographically relevant quantum computers

---

# DOMAIN 1

# QUANTUM-SAFE STORAGE ENGINE

## Responsibilities

Protect:

- Files
- Folders
- Documents
- Archives
- Secrets
- Certificates
- Keys
- Backups
- Source code
- Intellectual property

---

## Features

### Client-Side Encryption

Encrypt before upload.

Workflow:

File

↓

Generate DEK

↓

Encrypt Data

↓

Encrypt DEK

↓

Upload Ciphertext

---

### Cryptographic Envelope

Structure:

Encrypted Data

+

Encrypted DEK

+

Metadata

+

Integrity Proof

+

Version Information

---

### Chunked Encryption

Support:

- Large files
- Streaming uploads
- Resume transfers
- Parallel encryption

---

## KPIs

- Protected Assets
- Encrypted Files
- Encryption Throughput
- Storage Efficiency
- Upload Success Rate

---

# DOMAIN 2

# ZERO-KNOWLEDGE ARCHITECTURE

## Responsibilities

Ensure infrastructure cannot decrypt customer data.

---

## Requirements

### Server Never Sees

- Plaintext files
- Plaintext secrets
- Master keys

---

### Access Model

User

↓

Authentication

↓

Device Verification

↓

Key Recovery Validation

↓

Decryption

---

### Verification

Continuously verify:

- Encryption before upload
- Key isolation
- Metadata exposure
- Secret leakage

---

## KPIs

- Zero Knowledge Compliance
- Plaintext Exposure Events
- Encryption Validation Rate

---

# DOMAIN 3

# KEY MANAGEMENT ENGINE

## Responsibilities

Manage lifecycle of all cryptographic keys.

---

## Key Types

### Master Keys

Protect:

- User vaults
- Tenant vaults

---

### Data Encryption Keys

Protect:

- Files
- Objects
- Messages

---

### Sharing Keys

Protect:

- Secure links
- External sharing

---

### Recovery Keys

Protect:

- Disaster recovery
- Account recovery

---

## Lifecycle

Generate

↓

Distribute

↓

Use

↓

Rotate

↓

Archive

↓

Destroy

---

## Monitor

- Age
- Rotation status
- Usage
- Expiration
- Risk

---

## KPIs

- Active Keys
- Rotated Keys
- Expired Keys
- Weak Keys
- PQC-Protected Keys

---

# DOMAIN 4

# SECURE SHARING ENGINE

## Responsibilities

Provide controlled sharing without exposing cryptographic secrets.

---

## Sharing Types

### Internal Sharing

User-to-user

---

### Team Sharing

Role-based

---

### External Sharing

Temporary access

---

### Anonymous Sharing

Time-limited

Policy-controlled

---

## Security Controls

### Expiration

- Minutes
- Hours
- Days

---

### Download Limits

- Single-use
- Multi-use

---

### Geographic Restrictions

- Region-based access

---

### Device Restrictions

- Trusted devices only

---

### Watermarking

- Dynamic watermarks

---

## KPIs

- Shared Assets
- Expired Shares
- Revoked Shares
- Unauthorized Access Attempts

---

# DOMAIN 5

# QUANTUM KEY ESCROW & RECOVERY

## Responsibilities

Provide secure recovery mechanisms.

---

## Requirements

### Split Knowledge

No single recovery operator can access keys.

---

### Threshold Recovery

Examples:

- 2 of 3
- 3 of 5
- 5 of 7

---

### Recovery Approval

Require:

- Multiple approvers
- Audit trail
- Policy validation

---

## Monitor

- Recovery requests
- Recovery approvals
- Recovery failures

---

## KPIs

- Recovery Events
- Failed Recoveries
- Recovery Integrity Score

---

# DOMAIN 6

# CERTIFICATE & SECRET VAULT

## Responsibilities

Protect machine identities and secrets.

---

## Store

### Certificates

- TLS certificates
- Client certificates
- Device certificates

---

### Secrets

- API keys
- Tokens
- Service credentials

---

### Cryptographic Material

- Private keys
- Signing keys
- HSM backup keys

---

## Features

### Secret Rotation

Automated rotation

---

### Expiration Monitoring

Continuous validation

---

### Secret Health Scoring

Risk analysis

---

## KPIs

- Secrets Stored
- Expired Secrets
- Rotated Secrets
- High-Risk Secrets

---

# DOMAIN 7

# IMMUTABLE BACKUP & SNAPSHOT ENGINE

## Responsibilities

Provide recovery against deletion, ransomware, and corruption.

---

## Features

### Immutable Snapshots

Cannot be altered.

---

### Version History

Track:

- Changes
- Restores
- Deletes

---

### Point-in-Time Recovery

Restore:

- Files
- Folders
- Vaults

---

### Ransomware Protection

Detect:

- Mass encryption
- Mass deletion
- Abnormal behavior

---

## KPIs

- Snapshots Created
- Recovery Success Rate
- Backup Integrity
- Ransomware Events

---

# DOMAIN 8

# DATA INTEGRITY & AUTHENTICITY ENGINE

## Responsibilities

Ensure stored data remains authentic and untampered.

---

## Integrity Controls

### Cryptographic Hashing

- SHA3-256
- SHA3-512

---

### Merkle Tree Validation

Protect:

- Large files
- Vault collections

---

### Digital Signatures

Validate:

- Uploads
- Downloads
- Shares

---

## Detect

- Tampering
- Corruption
- Unauthorized modification

---

## KPIs

- Integrity Violations
- Signature Failures
- Validation Success Rate

---

# DOMAIN 9

# HARVEST NOW DEFENSE CENTER

## Responsibilities

Protect long-lived data against future quantum attacks.

---

## Identify

Data requiring protection:

### Critical

- Trade secrets
- Intellectual property
- Source code

---

### Sensitive

- Customer data
- Financial records
- Contracts

---

### Strategic

- Government information
- Research
- Long-term archives

---

## Calculate

### Harvest Risk Score

Factors:

- Data lifetime
- Sensitivity
- Adversary interest
- Regulatory impact

---

## Prioritize

- Immediate protection
- Enhanced protection
- Archive protection

---

## KPIs

- Harvest-Risk Assets
- Critical Exposure Score
- Long-Term Confidentiality Score

---

# DOMAIN 10

# VAULT TELEMETRY & OBSERVABILITY

## Responsibilities

Provide complete operational visibility.

---

## Monitor

### Storage

- Capacity
- Utilization
- Growth

---

### Cryptography

- Encryption events
- Key generation
- Key rotation
- Signature validation

---

### Security

- Login attempts
- Sharing events
- Recovery events
- Policy violations

---

### Performance

- Upload speed
- Download speed
- Encryption latency
- Decryption latency

---

## Required SSE Streams

- vault.uploads
- vault.downloads
- vault.deletions
- vault.restores
- vault.shares
- vault.revocations
- vault.encryption.events
- vault.decryption.events
- vault.keys.generated
- vault.keys.rotated
- vault.integrity.events
- vault.snapshot.events
- vault.recovery.events
- vault.harvest-risk.events

---

# AI-POWERED VAULT SECURITY

## Detect

### Abnormal Access

Examples:

- Impossible travel
- New device access
- Mass downloads

---

### Insider Threats

Examples:

- Bulk exports
- Unusual sharing

---

### Ransomware Indicators

Examples:

- Mass encryption
- Rapid modifications
- Bulk deletions

---

## Automated Actions

- Alert
- Lock session
- Suspend sharing
- Force MFA
- Require approval

---

# REQUIRED DASHBOARDS

## Executive Dashboard

- Vault Health Score
- Protected Assets
- Quantum Readiness
- Harvest Risk Exposure

---

## Security Dashboard

- Threat Activity
- Sharing Activity
- Recovery Activity
- Integrity Events

---

## Crypto Dashboard

- Encryption Metrics
- Key Lifecycle
- PQC Adoption
- Signature Health

---

## Operations Dashboard

- Storage Usage
- Upload Activity
- Performance Metrics
- Backup Status

---

# QGUARD HELIX QUANTUM VAULT OBJECTIVE

Answer these questions instantly:

1. Is my data quantum-safe?
2. Who can access my data?
3. Are my keys properly protected?
4. Has any file been tampered with?
5. Can I recover from ransomware?
6. Are secrets and certificates protected?
7. What data is vulnerable to Harvest Now, Decrypt Later attacks?
8. Are backups immutable and recoverable?
9. Is sharing secure and auditable?
10. Can long-term confidentiality be proven?

Success means every file, secret, certificate, key, backup, and shared object remains confidential, verifiable, recoverable, auditable, zero-knowledge, and quantum-safe throughout its entire lifecycle.

---

## Engineering knowledge base

This skill defines *what* to assess. For *how this codebase implements it* —
file locations, proven patterns, and issues already resolved — load:

- `qguard-security-practices`
- `qguard-common-issues-fixes` — check the symptom before debugging
- `qguard-knowledge-base` — index, and how to record new knowledge
