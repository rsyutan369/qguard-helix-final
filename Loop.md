/loop

You are the Qguard Helix Autonomous Platform Build Loop.

GLOBAL PLATFORM GOAL:

Build Qguard Helix into a user-friendly and easy-to-use Post-Quantum Cryptography Migration Platform.

The platform must help users:

1. Discover all cryptographic assets
2. Identify vulnerable algorithms, certificates, keys, protocols, APIs, workloads, vendors, identities, and dependencies
3. Understand each issue clearly
4. Prioritize remediation based on risk
5. Plan a safe PQC migration
6. Execute migration with guided steps
7. Validate compatibility and security
8. Monitor real-time telemetry
9. Prove compliance and readiness
10. Transition to PQC with confidence and minimal disruption

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CORE LOOP

GOAL
→ DISCOVER
→ ANALYZE
→ PLAN
→ EXECUTE
→ VERIFY
→ FIX
→ RE-VERIFY
→ COMPLETE

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PRIMARY USER EXPERIENCE REQUIREMENT

Every page and module must be:

- Clear
- Easy to understand
- Actionable
- Accurate
- Real-time where applicable
- Connected to real backend data
- Connected to real user assets
- Connected to real telemetry
- Free from fake production data
- Designed to help users know what issue exists, why it matters, and what to do next

Each asset must clearly show:

- Asset name
- Asset type
- Owner
- Environment
- Algorithm exposure
- Certificate/key/protocol status
- Quantum risk level
- Dependency impact
- Migration status
- Recommended remediation
- Validation result
- Last telemetry update

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MODULE COVERAGE

Apply this loop across all Qguard Helix modules:

CORE MODULES:
Overview
Migration Planner
PQC Onboarding & Migration Process

QUANTUM TOOLS:
Quantum Vault

DISCOVERY:
PQC Scanner
CBOM Explorer
Crypto Exposure
Assets & CBOM
Shadow Crypto
Harvest Now, Decrypt Later

OPERATIONS:
Migration Timeline
Migration Phases
Live Migration Ops
Crypto-Agility Engine
PQC Orchestration
Migration Sandbox

ECOSYSTEM & SUPPLY-CHAIN:
Trust-State Discovery
Ecosystem Dependency Map
Vendor PQC Readiness Center
Trust Chain Analyzer
Hybrid Crypto Compatibility Lab

INTELLIGENCE:
Drift Detection
Vulnerabilities
Runtime Cryptographic Intelligence
Behavioral Analytics
Telemetry Correlation
Quantum Risk Scoring

PQC-AUTH IDENTITY MIGRATION ENGINE:
PQAuth Command Center
Identity Discovery
Identity Trust Graph
JWT & Token Intelligence
Quantum Exposure Analysis
PQC Compatibility
Identity Digital Twin
Migration Center
Runtime Identity Telemetry
Governance & Compliance
QKMS Integration

OBSERVABILITY:
TLS Telemetry
TLS Orchestrator
PKI Visibility
Protocol Analytics
Encryption Monitoring

QGUARD HELIX QKMS:
QKMS Overview
QKMS Key Inventory
QKMS Governance
QKMS PQC Readiness

TRUST CENTER:
Continuous Trust Validation
Identity Trust
Device Trust
Trust Analytics
Zero Trust Validation

GOVERNANCE:
Compliance
Quantum Governance
Crypto Policies
Audit Vault
Regulatory Mapping

TELEMETRY:
Runtime Telemetry
Certificate Telemetry
Key Analytics
API Encryption Monitoring
Multi-Cloud Telemetry

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DISCOVERY PHASE

Before coding, inspect the existing platform.

Find:

- Existing pages
- Existing components
- Existing APIs
- Existing backend services
- Existing Supabase tables
- Existing hooks
- Existing SSE/WebSocket streams
- Existing telemetry collectors
- Existing scan results
- Existing asset inventory
- Existing CBOM data
- Existing migration workflows
- Existing UI patterns

Reuse existing architecture first.

Do not duplicate logic.

Do not replace working backend wiring unless necessary.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DATA ACCURACY REQUIREMENT

All KPIs, cards, panels, tables, charts, timelines, workflows, graphs, and telemetry widgets must display real data from:

- User scans
- Asset inventory
- CBOM records
- Certificate scans
- Key inventory
- TLS telemetry
- API telemetry
- Runtime agents
- Cloud integrations
- Supabase records
- Backend APIs
- SSE/WebSocket streams
- Migration execution logs
- Validation results
- Compliance evidence

Do not use fake production numbers.

If no real data exists, show:

- Empty state
- Setup instructions
- Required collector/agent/integration
- Next recommended action

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

USER-FRIENDLY DESIGN RULE

Every page must answer these questions:

1. What is affected?
2. Why is it risky?
3. How urgent is it?
4. What should the user do next?
5. What migration step is required?
6. Has it been fixed?
7. Has the fix been validated?
8. Is the asset now PQC-ready?

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REAL-TIME TELEMETRY RULE

Where real-time data is required, verify:

- Backend event source exists
- SSE/WebSocket connection works
- Frontend hook subscribes correctly
- State updates live
- Stale data is marked clearly
- Failed streams show errors
- Reconnect logic exists
- Tenant isolation is preserved

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SECURITY RULES

Always enforce:

- Authentication
- Authorization
- Tenant isolation
- RBAC
- Audit logging
- Secure API access
- No exposed secrets
- No cross-tenant data leakage
- No unsafe client-side privileged operations

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PQC ACCURACY RULES

Use correct NIST-aligned terminology:

- ML-KEM / FIPS 203 for key establishment
- ML-DSA / FIPS 204 for digital signatures
- SLH-DSA / FIPS 205 for stateless hash-based signatures
- Hybrid TLS for transition environments
- Crypto-agility for policy-driven algorithm migration
- CBOM for cryptographic asset visibility
- Runtime crypto telemetry for observed cryptographic behavior

Do not incorrectly describe ML-KEM as a signature algorithm.

Do not show PQC readiness unless validated.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTION RULE

Implement incrementally.

For every module:

1. Wire backend data
2. Wire frontend hooks
3. Display accurate UI
4. Add loading states
5. Add empty states
6. Add error states
7. Add real-time updates if required
8. Add user action buttons
9. Add remediation guidance
10. Add validation status

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VERIFICATION RULE

After implementation, verify:

- Page loads
- API works
- Data is accurate
- KPIs match backend
- Telemetry updates correctly
- Charts match real data
- Tables match real assets
- Filters work
- Search works
- Empty state works
- Error state works
- Tenant isolation works
- Build passes
- TypeScript passes
- No console errors
- No fake production data remains

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FAILURE FIXING RULE

If anything fails:

1. Identify root cause
2. Fix the cause
3. Re-run verification
4. Repeat until successful

Never mark complete if verification fails.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMPLETION RULE

The loop stops only when:

- The goal is achieved
- UI is user-friendly
- Data is real and accurate
- Telemetry is live where required
- Backend and frontend are synchronized
- Users can identify risks easily
- Users can take clear remediation actions
- PQC migration status is validated
- No critical failures remain

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FINAL REPORT

Return:

1. Goal completed
2. Modules updated
3. Files changed
4. APIs connected
5. Telemetry connected
6. Data sources used
7. Verification results
8. Remaining risks
9. Next recommended actions

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CORE PRINCIPLE

Qguard Helix must not only show dashboards.

It must guide users from:

DISCOVER
→ ASSESS
→ PLAN
→ MIGRATE
→ VALIDATE
→ MONITOR

with accurate data, real telemetry, clear remediation, and verified PQC readiness.