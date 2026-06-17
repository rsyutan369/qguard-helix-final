# REVIEW COMMAND

## Purpose

Perform enterprise-grade technical review of architecture, security, maintainability, performance, and production readiness.

Review is independent from build and verify.

Review focuses on quality, risk, and long-term sustainability.

---

# Review Areas

## Architecture Review

Evaluate:

* Scalability
* Maintainability
* Modularity
* Separation of concerns
* Technical debt

---

## Security Review

Evaluate:

* Authentication
* Authorization
* Secrets management
* Cryptography
* PQC compliance
* Trust boundaries

---

## Observability Review

Evaluate:

* Logging
* Telemetry
* Metrics
* Monitoring
* SSE architecture

---

## Performance Review

Evaluate:

* Database efficiency
* API latency
* Rendering performance
* Memory consumption
* Event processing

---

## QGuard Helix Domain Review

### Discovery

* Asset accuracy
* CBOM accuracy
* Crypto visibility

### Migration

* Safety
* Rollback readiness
* Dependency awareness

### Trust Fabric

* Relationship accuracy
* Dependency mapping

### Ecosystem

* Vendor visibility
* Supply-chain visibility

### Vault

* Zero-knowledge compliance
* PQC compliance
* Key lifecycle security

---

# Severity Levels

## CRITICAL

Production risk.

Must be fixed.

---

## HIGH

Security or reliability concern.

Should be fixed before release.

---

## MEDIUM

Improvement recommended.

---

## LOW

Optimization opportunity.

---

# Review Report

Provide:

## Strengths

What was done well.

## Risks

Potential issues.

## Recommendations

Suggested improvements.

## Production Readiness

One of:

* READY
* READY WITH CONDITIONS
* NOT READY

---

# Reviewer Independence

Reviewer must never:

* Assume functionality works
* Trust implementation claims
* Trust dashboard values
* Trust KPI values

Reviewer requires evidence.

---

# Core Principle

Trust evidence.

Question assumptions.

Protect production.
