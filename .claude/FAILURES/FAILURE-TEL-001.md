# FAILURE-TEL-001

Title

KPI Cards Display Inconsistent Telemetry Values

Failure ID

FAILURE-TEL-001

Severity

P1

Status

OPEN

Module

Telemetry

Owner

Telemetry Validator

---

# SUMMARY

Dashboard KPI cards display values that do not match across modules.

Observed:

* Different asset counts
* Different readiness values
* Different risk metrics

---

# EXPECTED BEHAVIOR

All KPI values must originate from a single authoritative backend source.

---

# IMPACT

Impact Level:

HIGH

Effects:

* User confusion
* Incorrect reporting
* Reduced trust

---

# INVESTIGATION PLAN

Verify:

[ ] Backend calculations

[ ] API outputs

[ ] SSE streams

[ ] Cache layers

[ ] Dashboard bindings

---

# SOURCE OF TRUTH ANALYSIS

Metric

Source

Verified

Asset Count

Unknown

No

Readiness Score

Unknown

No

Risk Score

Unknown

No

---

# EVIDENCE

Pending

---

# ROOT CAUSE

Not Identified

---

# FIX PLAN

Pending

---

# VERIFICATION REQUIREMENTS

* API validation
* SSE validation
* UI validation

---

# STATUS

OPEN
