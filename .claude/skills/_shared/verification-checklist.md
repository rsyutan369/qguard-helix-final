# Verification Checklist

## Purpose

This checklist is mandatory before any feature, module, dashboard, scanner, migration workflow, agent, operator patcher, API, or telemetry component is considered complete.

No module may be marked complete until every verification item passes.

---

# 1. Data Integrity Verification

## KPI Cards

Verify:

- Values are derived from real backend data
- No hardcoded production metrics
- No placeholder values
- Percentages are mathematically correct
- Totals match database records
- Counts match active tenant scope
- Time windows are accurate

Validation:

✓ Database query verified

✓ API response verified

✓ UI value matches backend value

---

## Charts

Verify:

- Chart values match source datasets
- Labels are accurate
- Time-series data uses correct timestamps
- Aggregations are correct
- Missing data handled properly
- Empty states implemented

Validation:

✓ Query verified

✓ Visualization verified

✓ Edge cases tested

---

## Tables

Verify:

- Pagination works
- Sorting works
- Filtering works
- Search works
- Export works

Validation:

✓ Data consistency verified

✓ Row count verified

✓ Tenant isolation verified

---

# 2. API Verification

For every API endpoint:

Verify:

- Authentication required
- Authorization enforced
- Input validation implemented
- Error handling implemented
- Rate limiting configured
- Audit logs generated

Validation:

✓ Request tested

✓ Response validated

✓ Error paths tested

✓ Security reviewed

---

# 3. Supabase Verification

Verify:

- RLS enabled
- Tenant isolation enforced
- Policies tested
- Indexes created
- Queries optimized
- No N+1 query patterns

Validation:

✓ RLS tested

✓ Performance tested

✓ Query plan reviewed

---

# 4. SSE / Realtime Verification

Verify:

- Connection established
- Reconnection supported
- Heartbeat implemented
- Events typed correctly
- Events reach UI
- Events update state

Validation:

✓ Backend event emitted

✓ Frontend event received

✓ UI updated

✓ Reconnect tested

---

# 5. Agent Verification

Verify:

- Agent receives correct scope
- Agent actions logged
- Rollback available
- Permissions enforced
- Audit trail generated

Validation:

✓ Simulation tested

✓ Production workflow tested

✓ Failure recovery tested

---

# 6. Migration Verification

Verify:

- Discovery data accurate
- Dependencies mapped
- Blast radius calculated
- Rollback created
- Snapshots generated
- Compliance evidence produced

Validation:

✓ Dry run completed

✓ Rollback tested

✓ Reports verified

---

# 7. Security Verification

Verify:

- Secrets not exposed
- Tokens protected
- Logs sanitized
- Encryption enabled
- Access controls enforced

Validation:

✓ Security review passed

✓ Vulnerability scan passed

✓ Secrets scan passed

---

# 8. UI Verification

Verify:

- Responsive design
- Accessibility compliance
- Empty states
- Error states
- Loading states
- Dark/light theme support

Validation:

✓ Desktop tested

✓ Tablet tested

✓ Mobile tested

---

# Release Gate

A module may proceed only when:

✓ Data verified

✓ Telemetry verified

✓ APIs verified

✓ Security verified

✓ UX verified

✓ Compliance verified

✓ Performance verified

Status:

PASS / FAIL