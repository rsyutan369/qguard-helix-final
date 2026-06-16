# Telemetry Rules

## Purpose

All telemetry displayed in QGuard Helix must originate from real assets, scans, agents, sensors, APIs, databases, or verified simulation engines.

Fake telemetry is prohibited.

---

# Golden Rules

## Rule 1

Never display fabricated production metrics.

Forbidden:

- Random numbers
- Mock security scores
- Placeholder risk scores
- Synthetic compliance percentages

---

## Rule 2

Every UI metric must have a source.

Required:

Metric
→ API
→ Database Query
→ SSE Event
→ Sensor
→ Asset

---

## Rule 3

Telemetry Must Be Traceable

Every metric must identify:

- Source
- Timestamp
- Tenant
- Asset
- Collector

Example:

TLS Vulnerable Endpoints

Source:
scanner_tls_results

Collector:
agent-01

Timestamp:
2026-01-12T08:20Z

---

# Real-Time Rules

## SSE Events

Must contain:

event_id

tenant_id

asset_id

timestamp

severity

event_type

payload

---

## Event Delivery

Required:

- Retry logic
- Reconnect logic
- Heartbeats
- Event ordering

---

# Dashboard Rules

## KPI Cards

Must display:

Current Value

Last Updated

Source

Confidence

---

# Risk Engine Rules

Risk scores must be derived from:

- Asset criticality
- Vulnerability severity
- Exposure
- Compliance status
- Threat intelligence

Never randomize scores.

---

# Scanner Rules

Scanner results must include:

- Asset scanned
- Scan time
- Scanner version
- Rule version
- Detection evidence

---

# Migration Rules

Migration telemetry must include:

- Current phase
- Progress
- Completed actions
- Failed actions
- Rollback status

---

# Audit Requirements

Every telemetry item must support:

- Historical replay
- Timeline reconstruction
- Compliance reporting
- Forensics review

---

# Telemetry Quality Score

Telemetry is considered valid only when:

✓ Source Verified

✓ Timestamp Valid

✓ Asset Linked

✓ Tenant Scoped

✓ Audit Logged

✓ Reproducible