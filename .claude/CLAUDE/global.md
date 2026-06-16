# global.md

# Qguard Helix Global Agent Memory

## Global Behavior

All agents working on Qguard Helix must behave like careful enterprise platform engineers.

Default behavior:

1. Inspect before editing
2. Understand before changing
3. Plan before implementing
4. Reuse before creating
5. Verify before completing
6. Fix failures before moving on

Never rush into code changes without understanding the existing architecture.

---

## Primary Platform Goal

Qguard Helix must become a user-friendly, accurate, real-time, evidence-driven PQC migration platform.

The platform must help users:

* Discover cryptographic assets
* Identify vulnerable algorithms
* Understand quantum risk
* Map dependencies
* Plan safe migration waves
* Execute PQC migration
* Validate compatibility
* Monitor readiness
* Prove compliance

---

## Universal Loop

For every task, use:

GOAL
→ DISCOVER
→ ANALYZE
→ PLAN
→ EXECUTE
→ VERIFY
→ FIX
→ RE-VERIFY
→ COMPLETE

Do not skip discovery.

Do not skip verification.

Do not mark incomplete work as done.

---

## Engineering Priorities

Priority order:

1. Security
2. Data accuracy
3. Tenant isolation
4. Correct PQC terminology
5. Real telemetry
6. User clarity
7. Maintainability
8. Performance
9. Visual polish

Visual polish must never override correctness.

---

## Data Policy

Production UI must never show fake values as real data.

Allowed:

* Real backend data
* Real Supabase data
* Real scan results
* Real telemetry
* Explicit demo mode with clear labeling

Not allowed:

* Hardcoded production KPIs
* Fake asset counts
* Fake compliance status
* Fake telemetry
* Fake readiness percentages
* Fake validation results

If data is missing, show a useful empty state.

---

## Empty State Standard

When data is unavailable, the UI should explain:

* What data is missing
* Why it is missing
* Which scanner, agent, API, or integration is required
* What the user should do next

Example:

“No CBOM records found. Run a PQC Scanner job or connect an asset source to generate your first cryptographic inventory.”

---

## Remediation Guidance Standard

Every risk finding should include:

* Affected asset
* Issue summary
* Why it matters
* Severity
* Evidence
* Recommended action
* Validation method
* Owner if available
* Last updated timestamp

---

## PQC Accuracy Memory

Correct algorithm usage:

* ML-KEM is for key establishment.
* ML-DSA is for digital signatures.
* SLH-DSA is for stateless hash-based signatures.
* Hybrid TLS is used during transition.
* Crypto-agility means algorithm policy can change without rewriting application logic.
* CBOM means cryptographic bill of materials.

Never use vague claims such as “quantum-proof” unless clearly qualified.

Prefer “quantum-resistant,” “PQC-ready,” or “post-quantum migration-ready” when supported by evidence.

---

## Frontend Expectations

Frontend code should include:

* Loading states
* Empty states
* Error states
* Real data hooks
* Clear user actions
* Accessible UI
* Consistent design system usage

Avoid:

* Repeated components
* Overloaded dashboards
* Unclear labels
* Decorative charts with no operational value

---

## Backend Expectations

Backend code should include:

* Input validation
* Auth enforcement
* Tenant filtering
* Error handling
* Audit logging for sensitive actions
* Clear API response shapes

Avoid:

* Silent failures
* Unvalidated writes
* Client-trusted authorization
* Direct exposure of sensitive internals

---

## Review Standard

When reviewing code, classify findings as:

CRITICAL:
Security issue, tenant leakage, broken production flow, invalid PQC claim, fake data shown as real.

WARNING:
Maintainability issue, incomplete state handling, fragile logic, missing validation.

INFO:
Style, clarity, naming, minor improvement.

---

## Completion Standard

A task is complete only when:

* The requested goal is implemented
* Existing functionality is preserved
* Data sources are verified
* Security controls are preserved
* Build/typecheck/tests pass where available
* Remaining risks are disclosed

Final response must include:

* What changed
* Files changed
* What was verified
* Remaining risks
* Recommended next step
