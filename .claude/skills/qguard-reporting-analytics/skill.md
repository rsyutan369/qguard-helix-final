---
name: qguard-reporting-analytics
description: Reporting, scoring and analytics knowledge for QGuard Helix — the reporting engine, executive reports, risk and quantum-readiness scoring, evidence quality, CBOM generation and asset inventory counting rules. Use when building or fixing a report, a score, an assessment calculation, a CBOM view or any dashboard KPI.
priority: high
owner: qguard-helix
version: 1.0
---

# Reporting, Scoring & Analytics

## The reporting engine

`src/services/reporting` — the Enterprise Reporting Engine: 7 export formats, a
unified report model, lazy-loaded exporters. It powers Report Center.

PDF generation uses **`pdf-lib`**, not `react-pdf`. Exporters are lazy so a
format nobody used is never loaded.

## Scoring — one model, honestly reported

The platform grades on the **published twelve-category model**
(`SCORE_CATEGORY_DEFS`) with the shared `grading-model` table, so a host assessed
by the public scanner and by the authenticated scanner is graded on one scale.

Rules that took nine rounds of corrections to settle:

- **Unmeasured dimensions are excluded and their weight redistributed.** They are
  never scored 0 (a failure they did not earn) or 100 (a pass they did not earn).
  Carry `applicable` + `measuredWeight` so consumers can tell.
- **Report the decomposition beside the composite.** `summary.qScore` and the
  weighted decomposition are the same number only when the summary came from the
  weighted model; a summary rebuilt from stored findings by severity count
  diverges. Show both and explain, rather than letting one overwrite the other.
- **Calibrated risk decomposition, honest methodology, explicit confidence
  taxonomy.** A confidence score with no stated basis is decoration.
- **Canonical counts.** Reconcile bars, timeline and finding counts against one
  source before rendering.

## Two readiness scales — by design

The web scanner emits a 0–1000 Q-Score; the QR/report engine recomputes its own
0–100 readiness from DB rows. **These measure different things. Do not
"reconcile" them.** Label each with its source. The failure mode is silent
substitution, not coexistence.

## Counting rules — where totals come from

The alignment that fixed the Assets-vs-QR mismatch:

- The canonical vulnerable unit is the **COMPONENT**:
  `summary.vulnerableComponents === cbom.quantumVulnerableComponents`.
- `vulnerableCount` is **component-level**.
- `findingsCount` / `findingSignalCount` are **finding-level**.

Mixing a component count with a finding count in one sentence is the most common
way a report becomes wrong while every individual number stays true.

## Deduplication in reports

Duplicate rows in the SR matrix and Critical/High evidence tables were caused by
**keying on raw location**. The consolidation contract:

- Distinguish the **canonical asset key** from the **display label**.
- Aggregate `occurrences`; leave totals untouched.
- Hoist playbooks and approvals to the consolidated row.

Consolidating rows must never change a total. If it does, the dedup key is wrong.

## Executive reporting

Board-level output needs: a Board Snapshot, a 5×5 heat map, a priority matrix,
evidence-quality grades and remediation campaigns. Every compliance status links
back to supporting evidence — a status with no evidence link is not auditable.

Recommendations are generated from actual findings and carry priority, risk,
impact, remediation and migration guidance. A recommendation with no observed
finding behind it must say so.

## CBOM generation

CBOM records are written by the scanner into the shared tables and recomputed by
the CBOM view — never copied. Component identity must be stable across scans, or
the same component appears as new every run.

## Evidence and confidence

- Every finding links to supporting evidence, severity, affected asset,
  remediation and a confidence score.
- Confidence comes from measured coverage, not from a constant.
- Coverage is `measured / applicable` — modules that legitimately did not apply
  leave the denominator (see `qguard-scanner-orchestration`).

## Checklist

- [ ] Score uses the published category model, weight redistributed for
      unmeasured dimensions.
- [ ] Composite and decomposition both reported; divergence explained.
- [ ] Component counts and finding counts never conflated.
- [ ] Dedup preserves totals; canonical key ≠ display label.
- [ ] Every status links to evidence.
- [ ] Confidence has a stated basis.
- [ ] Cross-checked against the dashboard the report describes.
