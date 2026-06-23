# FAILURE-DISC-001

Title

Duplicate Vulnerabilities Across Discovery Modules

Failure ID

FAILURE-DISC-001

Severity

P1

Status

OPEN

Module

Discovery

Owner

Discovery Engineer

Created

2026-XX-XX

---

# SUMMARY

Duplicate vulnerabilities appear across multiple discovery views.

Affected Areas:

* PQC Scanner
* Crypto Exposure
* Assets & CBOM
* Risk Scoring

This may inflate vulnerability counts and readiness calculations.

---

# OBSERVED BEHAVIOR

Examples:

* Same vulnerability displayed multiple times
* Risk scores differ between pages
* Asset counts inconsistent

---

# EXPECTED BEHAVIOR

Each vulnerability should appear once.

Duplicates should be merged before:

* Scoring
* Reporting
* Dashboard display

---

# BUSINESS IMPACT

Impact Level:

HIGH

Potential Effects:

* Incorrect risk scores
* Incorrect readiness scores
* Loss of customer trust
* Reporting inaccuracies

---

# SUSPECTED ROOT CAUSES

Potential Causes:

[ ] Duplicate scanner results

[ ] Asset correlation issue

[ ] CBOM aggregation issue

[ ] API duplication

[ ] Database duplication

[ ] Frontend rendering duplication

---

# INVESTIGATION PLAN

Step 1

Verify database records.

Status:

PENDING

---

Step 2

Verify API responses.

Status:

PENDING

---

Step 3

Verify aggregation logic.

Status:

PENDING

---

Step 4

Verify frontend rendering.

Status:

PENDING

---

# EVIDENCE

Evidence Files:

Pending

Screenshots:

Pending

Logs:

Pending

---

# ROOT CAUSE

Status:

NOT IDENTIFIED

---

# FIX PLAN

Status:

NOT STARTED

---

# VERIFICATION

Required:

* Database validation
* API validation
* Telemetry validation
* UI validation

Status:

PENDING

---

# LESSONS LEARNED

Move final lessons to:

LESSONS.md

---

# CLOSURE

Status:

OPEN
