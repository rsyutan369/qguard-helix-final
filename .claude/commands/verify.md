# VERIFY COMMAND

## Purpose

Validate that implementation is correct, functional, secure, and backed by evidence.

Verification is the source of truth.

No feature is considered complete until verification passes.

---

# Verification Areas

## Frontend

Verify:

* Pages load
* Components render
* Navigation works
* State updates correctly
* Responsive layouts function

---

## Backend

Verify:

* APIs respond correctly
* Error handling works
* Authentication works
* Authorization works
* Database writes succeed

---

## Telemetry

Verify:

* Metrics are real
* Data originates from assets
* KPIs match backend values
* Charts match telemetry
* Dashboards match evidence

---

## SSE & Realtime

Verify:

* Streams connect
* Updates are received
* Events are processed
* UI updates correctly

---

## Security

Verify:

* Authentication
* Authorization
* Input validation
* Secrets handling
* Cryptographic implementation

---

## QGuard Helix Specific

Verify:

### Discovery

* Assets match scans
* CBOM data matches findings
* Crypto inventory is accurate

### Migration

* Plans match assets
* Progress reflects reality
* Rollback functions correctly

### Scanner

* Findings match evidence
* Vulnerabilities are valid
* False positives minimized

### Vault

* Encryption works
* Decryption works
* Sharing works
* Audit logs exist

---

# Verification Report

Provide:

## Passed Checks

List all successful validations.

## Failed Checks

List all failures.

## Evidence

Provide logs and proof.

## Regression Findings

Identify anything newly broken.

---

# Failure Rules

Verification fails if:

* Data is fake
* Metrics are incorrect
* APIs fail
* Telemetry is fabricated
* Regression exists
* Security controls fail

---

# Success Criteria

Success requires:

* Evidence
* Logs
* Verification output
* No critical failures

Never report success without proof.
