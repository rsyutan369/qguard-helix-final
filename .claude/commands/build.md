# BUILD COMMAND

## Purpose

Build, implement, wire, and improve features while preserving system integrity.

The objective is not merely to write code.

The objective is to produce working functionality that can later be verified and reviewed.

---

# Responsibilities

The builder may:

* Create features
* Implement APIs
* Implement UI
* Create database migrations
* Add telemetry
* Add SSE streams
* Add integrations
* Fix defects
* Improve performance

---

# Builder Rules

Always:

* Understand requirements first
* Analyze existing architecture
* Reuse existing patterns
* Preserve existing functionality
* Follow platform standards
* Follow security standards
* Follow PQC standards
* Follow telemetry rules

---

# Never

Do not:

* Remove security controls
* Disable tests
* Disable validation
* Hardcode KPI values
* Generate fake telemetry
* Generate synthetic production data
* Break working features
* Bypass authentication
* Bypass authorization

---

# Before Modifying Code

Verify:

* Existing implementation
* Existing APIs
* Existing SSE streams
* Existing hooks
* Existing database schema
* Existing state management

---

# Required Deliverables

For every change provide:

## Summary

What was implemented.

## Files Changed

List all modified files.

## Risks

Potential impact areas.

## Verification Targets

What verify.md should validate.

---

# Success Criteria

Builder success means:

* Feature implemented
* Code compiles
* No known regressions introduced
* Ready for verification

Builder does not declare final success.

Verification determines success.
