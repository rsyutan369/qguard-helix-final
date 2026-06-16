# Security Standards

## Purpose

Defines minimum security requirements for all QGuard Helix services, APIs, agents, scanners, and migration engines.

---

# Zero Trust Principles

Always:

- Verify Explicitly
- Least Privilege
- Assume Breach

---

# Authentication

Required:

- MFA
- Session Protection
- Token Rotation
- Device Validation

---

# Authorization

Required:

- RBAC
- Tenant Isolation
- Fine-Grained Permissions

---

# Secrets Management

Never:

- Store secrets in code
- Store secrets in repositories
- Store secrets in logs

Use:

- Environment Variables
- Secret Managers
- HSM Integration

---

# Encryption Standards

Data In Transit:

TLS 1.3

Hybrid TLS Preferred

X25519 + ML-KEM-768

---

Data At Rest:

AES-256-GCM

---

# Logging Standards

Must Log:

- Authentication
- Authorization
- Asset Changes
- Policy Changes
- Migration Events
- Agent Actions

---

# Audit Standards

All actions must record:

- User
- Timestamp
- Action
- Resource
- Result

---

# Secure Development

Required:

- Code Review
- SAST
- Dependency Scanning
- Secret Scanning
- Container Scanning

---

# API Security

Required:

- JWT Validation
- Input Validation
- Rate Limiting
- CSRF Protection
- CORS Validation

---

# Database Security

Required:

- RLS
- Encryption
- Backups
- PITR

---

# Agent Security

Required:

- Signed Commands
- Audit Logging
- Rollback Capability
- Approval Workflow

---

# Compliance Alignment

- NIST CSF 2.0
- NIST SP 800-53
- ISO 27001
- SOC 2
- CIS Controls
- PCI DSS