# project.md

# Qguard Helix Project Memory

## Project Name

Qguard Helix

## Project Type

Enterprise Post-Quantum Cryptography migration, discovery, telemetry, governance, trust, and crypto-agility platform.

## Domain

qguardhelix.com

## Product Direction

Qguard Helix is designed to help organizations transition from classical cryptography to post-quantum cryptography safely and clearly.

The platform should not only show dashboards.

It should guide users through:

DISCOVER
→ ASSESS
→ PLAN
→ MIGRATE
→ VALIDATE
→ MONITOR
→ GOVERN

---

## Current Technical Stack

Frontend:

* React
* TypeScript
* Vite
* Tailwind
* ShadCN-style components
* Framer Motion where useful

Backend:

* Express API
* Supabase
* Server-side validation
* Authenticated user context

Runtime notes:

* `src/main.tsx`, `src/App.tsx`, and `src/app/**` contain the browser application.
* `src/api-server/**` contains the active backend API.
* Vite mounts the Express API during development through `vite.config.ts`.
* `src/api-server/standalone.ts` serves the built Vite app and Express API from one Node process.
* `src/app/api/**/route.ts` files are legacy Next-style route files unless verified otherwise.

---

## Core Product Modules

### Core

* Overview
* Migration Planner
* PQC Onboarding & Migration Process

### Quantum Tools

* Quantum Vault

### Discovery

* PQC Scanner
* CBOM Explorer
* Crypto Exposure
* Assets & CBOM
* Shadow Crypto
* Harvest Now, Decrypt Later

### Operations

* Migration Timeline
* Migration Phases
* Live Migration Ops
* Crypto-Agility Engine
* PQC Orchestration
* Migration Sandbox

### Ecosystem & Supply Chain

* Trust-State Discovery
* Ecosystem Dependency Map
* Vendor PQC Readiness Center
* Trust Chain Analyzer
* Hybrid Crypto Compatibility Lab

### Intelligence

* Drift Detection
* Vulnerabilities
* Runtime Cryptographic Intelligence
* Behavioral Analytics
* Telemetry Correlation
* Quantum Risk Scoring

### PQAuth Identity Migration Engine

* PQAuth Command Center
* Identity Discovery
* Identity Trust Graph
* JWT & Token Intelligence
* Quantum Exposure Analysis
* PQC Compatibility
* Identity Digital Twin
* Migration Center
* Runtime Identity Telemetry
* Governance & Compliance
* QKMS Integration

### Observability

* TLS Telemetry
* TLS Orchestrator
* PKI Visibility
* Protocol Analytics
* Encryption Monitoring

### QKMS

* QKMS Overview
* QKMS Key Inventory
* QKMS Governance
* QKMS PQC Readiness

### Trust Center

* Continuous Trust Validation
* Identity Trust
* Device Trust
* Trust Analytics
* Zero Trust Validation

### Governance

* Compliance
* Quantum Governance
* Crypto Policies
* Audit Vault
* Regulatory Mapping

### Telemetry

* Runtime Telemetry
* Certificate Telemetry
* Key Analytics
* API Encryption Monitoring
* Multi-Cloud Telemetry

---

## Product UX Principle

Qguard Helix should be easy to use even though PQC is complex.

Every page should clearly show:

* Current status
* Risk level
* Affected assets
* Evidence
* Recommended next step
* Migration readiness
* Validation result

Avoid making users interpret raw cryptographic data without guidance.

---

## Migration Planner Goal

The Migration Planner should help users:

* Select assets
* Understand quantum exposure
* Group assets into migration waves
* View dependencies
* Prioritize remediation
* Track readiness
* Validate migration safety
* Move toward live migration

---

## PQC Onboarding Goal

PQC Onboarding should help users:

* Understand the migration journey
* Connect integrations
* Configure scanners
* Deploy agents or collectors where needed
* Build the first asset inventory
* Generate baseline crypto posture
* Start migration planning

---

## Scanner Goal

PQC Scanner should discover:

* TLS endpoints
* Certificates
* Keys
* Algorithms
* Protocols
* APIs
* Cloud crypto usage
* Runtime crypto behavior
* Shadow crypto
* Weak or deprecated cryptography

---

## CBOM Goal

CBOM features should map:

* Cryptographic assets
* Algorithms
* Libraries
* Certificates
* Keys
* Protocols
* Owners
* Dependencies
* Risk evidence

CBOM data should support migration planning and governance.

---

## Trust Fabric Goal

Trust modules should show:

* Who trusts whom
* Which certificates anchor trust
* Which identities depend on which systems
* Which vendors or dependencies may break
* Which trust chains need PQC migration

---

## PQAuth Goal

PQAuth Identity Migration Engine should help organizations migrate identity and authentication systems toward PQC readiness.

It should analyze:

* OAuth/OIDC flows
* JWTs
* Tokens
* Signing algorithms
* Identity providers
* Trust graphs
* Runtime identity telemetry

---

## QKMS Goal

QKMS should manage and govern key posture, lifecycle, and PQC readiness.

Key operations are high sensitivity.

Never implement key handling casually.

---

## Governance Goal

Governance modules should provide:

* Evidence-backed compliance status
* Audit trails
* Crypto policy mapping
* Regulatory readiness
* PQC migration governance

Never fabricate compliance evidence.

---

## Local Development URLs

Important local routes include:

* `http://localhost:3000/dashboard/overview`
* `http://localhost:3000/dashboard/migration-planner`
* `http://localhost:3000/dashboard/pqc-onboarding`
* `http://localhost:3000/dashboard/scanner`
* `http://localhost:3000/dashboard/cbom`
* `http://localhost:3000/dashboard/live-migration`
* `http://localhost:3000/dashboard/pqc-orchestration`
* `http://localhost:3000/dashboard/migration-sandbox`

Verify actual routes in the codebase before assuming route names.

---

## Working Rule

For each module:

1. Inspect the existing implementation
2. Identify real data sources
3. Identify fake or placeholder data
4. Verify APIs and Supabase queries
5. Verify SSE/WebSocket telemetry if used
6. Improve UX clarity
7. Add empty/error/loading states
8. Fix broken wiring
9. Run verification
10. Report results

Do not proceed to unrelated modules unless explicitly instructed.
