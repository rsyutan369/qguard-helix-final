# Qguard Helix Engineering Standards

Qguard Helix is an enterprise-grade Post-Quantum Cyber Defense platform focused on cryptographic discovery, quantum-risk assessment, PQC migration, cryptographic governance, secure communications, and quantum-safe data protection.

## Core Principles

1. Security First
2. Zero Trust Architecture
3. Post-Quantum Ready
4. Multi-Tenant Safe
5. Enterprise Grade Reliability
6. Production Quality Code
7. Observable Systems
8. Privacy By Design

---

## Technology Stack

Frontend:

* Next.js
* React
* TypeScript
* Tailwind CSS
* Shadcn UI
* Framer Motion

Backend:

* FastAPI
* Python
* Supabase
* PostgreSQL
* Redis
* Celery

Infrastructure:

* Docker
* Kubernetes
* NGINX
* Cloudflare

Observability:

* Prometheus
* Grafana

---

## Cryptography Standards

Hybrid Key Exchange:

* X25519 + ML-KEM-768

Vault Encryption:

* ML-KEM-1024

Digital Signatures:

* Ed25519
* ML-DSA-65

Encryption:

* AES-256-GCM

Hashing:

* SHA3-256

KDF:

* HKDF-SHA3-256

---

## Security Requirements

Mandatory:

* No hardcoded secrets
* No plaintext sensitive data
* No disabled security controls
* No cross-tenant access
* No bypassing RLS
* No insecure cryptography
* No unsafe deserialization
* No SQL injection risks
* No XSS risks
* No SSRF risks

---

## SaaS Isolation

Every query must enforce:

* user_id validation
* tenant_id validation
* Row Level Security
* Ownership verification

No user may access another user's:

* Vault files
* Messages
* Keys
* Scan results
* Migration plans
* Compliance reports

---

## Development Expectations

All code should:

* Be production ready
* Include error handling
* Include validation
* Be strongly typed
* Be maintainable
* Be secure by default

Prioritize security, reliability, and correctness over speed of implementation.
