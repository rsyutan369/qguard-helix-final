# CLAUDE.md

# Qguard Helix Engineering Constitution

## Platform Mission

Qguard Helix is an enterprise Post-Quantum Cryptography (PQC) discovery, migration, governance, telemetry, and crypto-agility platform.

The purpose of the platform is to help organizations:

* Discover cryptographic assets
* Identify quantum-vulnerable systems
* Understand cryptographic dependencies
* Plan PQC migrations
* Execute migrations safely
* Validate readiness
* Continuously monitor cryptographic posture
* Maintain compliance and governance

The platform must prioritize:

1. Accuracy
2. Security
3. Usability
4. Explainability
5. Evidence-driven decision making
6. Real-time visibility
7. Multi-tenant isolation

---

# Core User Journey

Every module must support the lifecycle:

DISCOVER
→ ASSESS
→ PLAN
→ MIGRATE
→ VALIDATE
→ MONITOR
→ GOVERN

Every page should help users answer:

1. What is affected?
2. Why is it risky?
3. How urgent is it?
4. What should I do next?
5. Has it been remediated?
6. Has remediation been verified?
7. Is the asset PQC-ready?

---

# Platform Architecture

## Frontend

React
TypeScript
Vite
Tailwind
ShadCN
Framer Motion

Frontend responsibilities:

* Visualization
* User workflows
* Telemetry rendering
* Asset management
* Migration orchestration UI
* Governance dashboards

Frontend must never own privileged security logic.

---

## Backend

Node.js
Express
Supabase

Backend responsibilities:

* Secure operations
* Asset processing
* Scan orchestration
* Telemetry aggregation
* Migration workflows
* Compliance evidence
* Trust analytics

---

## Data Layer

Supabase remains the source of truth.

Never bypass tenant boundaries.

Never trust client-side authorization.

All sensitive actions must be validated server-side.

---

# Development Philosophy

Before creating anything:

1. Discover existing implementation
2. Reuse existing architecture
3. Extend existing functionality
4. Avoid duplication
5. Verify data sources
6. Validate assumptions

Never create duplicate services when one already exists.

---

# Universal Development Loop

For every request:

GOAL
→ DISCOVER
→ ANALYZE
→ PLAN
→ EXECUTE
→ VERIFY
→ FIX
→ RE-VERIFY
→ COMPLETE

Implementation alone is not success.

Verification is success.

---

# Data Accuracy Rules

All KPIs, dashboards, charts, cards, graphs, timelines, and telemetry must originate from:

* Real scans
* Real assets
* Real telemetry
* Real certificates
* Real keys
* Real APIs
* Real cloud integrations
* Real migration records
* Real compliance evidence

Do not generate fake production metrics.

Do not hardcode security posture data.

Do not fabricate telemetry.

When no data exists:

Show:

* Empty state
* Setup instructions
* Integration guidance
* Recommended next action

---

# Telemetry Standards

Real-time telemetry must be verified end-to-end.

Validate:

* Event source exists
* Backend stream exists
* API exists
* SSE/WebSocket exists
* Frontend subscription exists
* UI updates correctly
* Reconnection works
* Tenant isolation is maintained

No simulated telemetry in production.

---

# Security Standards

Always enforce:

* Authentication
* Authorization
* RBAC
* Tenant isolation
* Audit logging
* Principle of least privilege
* Secure API design
* Secure secret handling

Never expose:

* Service role keys
* Secrets
* Credentials
* Internal tokens

Never trust client input without validation.

---

# PQC Standards

Use correct terminology.

Approved standards:

Key Establishment:

* ML-KEM (FIPS 203)

Digital Signatures:

* ML-DSA (FIPS 204)
* SLH-DSA (FIPS 205)

Symmetric:

* AES-256-GCM

Hashing:

* SHA3-256
* SHA3-512

Hybrid deployments may combine:

* X25519 + ML-KEM
* Ed25519 + ML-DSA

Never describe ML-KEM as a signature algorithm.

Never mark assets PQC-ready without validation.

---

# User Experience Principles

Qguard Helix must remain understandable to:

* Security engineers
* Architects
* CISOs
* Compliance teams
* Platform teams
* Identity teams

Complex cryptography must be translated into actionable business guidance.

Every page should provide:

* Risk visibility
* Asset ownership
* Dependencies
* Recommended actions
* Validation status

Avoid dashboard clutter.

Avoid security jargon without explanation.

---

# Discovery Modules

Modules:

* PQC Scanner
* CBOM Explorer
* Assets & CBOM
* Crypto Exposure
* Shadow Crypto
* Harvest Now Decrypt Later

Requirements:

* Accurate inventory
* Accurate crypto identification
* Dependency awareness
* Ownership visibility
* Risk scoring

---

# Operations Modules

Modules:

* Migration Planner
* Migration Timeline
* Live Migration Ops
* Crypto Agility Engine
* PQC Orchestration
* Migration Sandbox

Requirements:

* Guided workflows
* Rollback capability
* Validation checkpoints
* Change visibility
* Execution transparency

---

# Ecosystem & Supply Chain Modules

Modules:

* Trust-State Discovery
* Ecosystem Dependency Map
* Vendor PQC Readiness
* Trust Chain Analyzer
* Hybrid Crypto Compatibility Lab

Requirements:

* Dependency mapping
* Blast radius analysis
* Compatibility testing
* Vendor readiness visibility

---

# Intelligence Modules

Modules:

* Runtime Cryptographic Intelligence
* Behavioral Analytics
* Drift Detection
* Telemetry Correlation
* Quantum Risk Scoring

Requirements:

* Explainable insights
* Evidence-backed findings
* Confidence scoring
* Traceable reasoning

---

# PQAuth Identity Migration Engine

Modules:

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

Requirements:

* Identity visibility
* Trust relationship analysis
* Token intelligence
* Migration planning
* Runtime validation

---

# QKMS

Responsibilities:

* Key inventory
* Key lifecycle
* Governance
* PQC readiness
* Crypto policy enforcement

QKMS is the platform trust anchor.

Treat all key operations as high sensitivity.

---

# Trust Center

Modules:

* Continuous Trust Validation
* Identity Trust
* Device Trust
* Trust Analytics
* Zero Trust Validation

Trust scores must be evidence-based.

No synthetic trust calculations without supporting evidence.

---

# Governance

Modules:

* Compliance
* Quantum Governance
* Crypto Policies
* Audit Vault
* Regulatory Mapping

Governance findings must be traceable.

Every compliance status should link back to supporting evidence.

---

# Code Quality Standards

Required:

* Strong typing
* Reusable components
* Modular architecture
* Error handling
* Loading states
* Empty states
* Auditability

Avoid:

* Dead code
* Hardcoded values
* Unused services
* Duplicate APIs
* Duplicate telemetry pipelines

---

# Verification Requirements

Before marking work complete:

Verify:

Frontend:

* Pages render
* Navigation works
* Filters work
* Search works

Backend:

* APIs respond
* Validation works
* Authorization works

Data:

* KPIs accurate
* Charts accurate
* Tables accurate

Realtime:

* Telemetry updates
* SSE works
* WebSockets work

Security:

* No tenant leakage
* No exposed secrets

Build:

* TypeScript passes
* Build succeeds
* No console errors

---

# Completion Criteria

Work is complete only when:

* Goal achieved
* Data accurate
* Telemetry verified
* Security validated
* User workflow functional
* Migration guidance actionable
* Production readiness confirmed

Never stop at implementation.

Stop only after verification succeeds.
