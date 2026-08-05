---
name: qguard-data-integrity
description: The Single Source of Truth contract for QGuard Helix. Use whenever adding or changing ANY value the UI displays — a KPI, score, grade, count, percentage, chart series or table total — or when two panels disagree, a number looks fabricated, or a dashboard must stay in lock-step with reports and downstream engines.
priority: critical
owner: qguard-helix
version: 1.0
---

# Data Integrity — Single Source of Truth

The most frequently violated contract in the platform. Every "the dashboard is
wrong" report traces back to one of the rules below.

## Rule 1 — One computation, many readers

A value is computed in exactly ONE place. Panels read that value; they never
recompute it.

```ts
// WRONG — two opinions that will drift
const heroScore   = 100 - summary.riskScore
const panelScore  = weightedMean(scoreCategories)

// RIGHT — one derivation, shared
const assessment = buildAssessment(input)   // the only place posture is decided
<Hero   score={assessment.executive.encryptionScore} />
<Panel  score={assessment.executive.encryptionScore} />
```

In practice: `buildAssessment()` in
`src/app/dashboard/scanner_dashboard/_intel.ts` is the scanner surface's single
derivation. Every result panel takes `assessment` — not raw state.

## Rule 2 — Pick the scope once

The bug that produced "Grade A · 96%" beside "106 critical findings".

```ts
// WRONG — each field independently picks a population
critical: summary?.critical ?? estate.criticalFindings,
total:    summary?.totalFindings ?? estate.totalFindings,

// RIGHT — one decision, every field follows
const scope: 'scan' | 'estate' = summary ? 'scan' : 'estate'
```

**Never** write `a ?? b` where `a` and `b` describe different populations. A
per-field fallback is a scope decision in disguise.

Every panel must also *state* the scope it describes ("across this assessment" /
"across the tenant estate"), so a reader can tell without inspecting code.

## Rule 3 — Unmeasured is not zero

Three states must remain distinguishable:

| State | Renders as |
|---|---|
| Measured, good | the value |
| Measured, bad | the value |
| **Not measured** | Unknown / Not probed / Not applicable **with a reason** |

Never render "not measured" as `0`, as `100`, or as a pass. When a weighted model
has an unmeasured dimension, **exclude it and redistribute its weight** — do not
substitute a filler. Carry an `applicable` flag alongside every score so
consumers can tell a measurement from a placeholder.

## Rule 4 — Ownership is total and unique

Each observation belongs to exactly one owner, and it must be the component that
produced it. Otherwise per-item counts will not sum to the headline total.

Order matters when classifying by string:

```ts
// Code-origin categories BEFORE algorithm-class tests, or
// "Web Crypto (hash)" is filed under the certificate hash analyzer.
if (category.includes('source code') || category.includes('web crypto')) return 'dependency-crypto-scanner'
if (category.includes('hash')) return 'hash-algorithm-scanner'

// `includes('symmetric')` ALSO matches "asymmetric" — match exactly.
if (category === 'symmetric encryption') return 'cipher-suite-scanner'
```

Always add a test asserting `sum(perItemCounts) === total`.

## Rule 5 — Derive, don't duplicate, cross-cutting routing

Two independently-maintained tables of the same rule WILL drift. Derive one from
the other.

```ts
// Finding → surface goes through finding → module → surface, so the
// backend's ownership and the UI's grouping cannot disagree.
export function nodeForFindingCategory(category, detectionMethod = '', algorithm = '') {
  return MODULE_NODE[moduleIdForFinding({ category, detectionMethod, algorithm })] ?? 'posture'
}
```

`scanner-module-ledger.ts` is deliberately **pure and dependency-free** (no
Express, no Supabase) precisely so the frontend can import it and share the rule
rather than reimplement it.

## Rule 6 — Withhold verdicts the evidence does not support

A grade is a claim about a whole estate. Gate it:

```ts
const runSettled = !live && unreportedModules.length === 0
const gradeable  = hasEvidence && runSettled
```

An incomplete run reports "Incomplete run — N modules never reported" rather than
a letter. Withholding is always safer than asserting.

## Rule 7 — Two scales that measure different things are not "inconsistent"

The web scanner emits a 0–1000 Q-Score; the QR engine emits its own 0–100
readiness recomputed from DB rows. These are different measurements of different
populations. **Do not "reconcile" them.** Label each with its source. What must
never happen is one number being *silently substituted* for the other.

Where two numbers *should* agree but might not, report both and explain the
divergence rather than letting one overwrite the other (`decompositionScore`
beside `encryptionScore`).

## Rule 8 — Persistence is the shared truth

Scanner writes `assets`, `crypto_inventory`, `pqc_scan_results`,
`crypto_exposures`, `certificates`, `pqc_scan_sessions`. CBOM, Assets, Exposure,
Quantum Readiness and Reports **recompute from those same rows**. Cross-module
consistency holds because the rows are shared, not because the numbers are copied.

Never write a derived metric into a table that another module treats as raw input.

## Review checklist

Before merging any change that touches a displayed value:

- [ ] The value is computed once and read everywhere else.
- [ ] No `??` fallback spans two different populations.
- [ ] Unmeasured renders as Unknown/Not-applicable **with a reason**.
- [ ] Weight is redistributed for unmeasured dimensions; nothing is filled in.
- [ ] Per-item counts sum to the displayed total (asserted by a test).
- [ ] Cross-cutting routing is derived from one rule, not duplicated.
- [ ] Verdicts are withheld when the run is incomplete.
- [ ] Each panel states the scope it is describing.
- [ ] `tools/scanner-dashboard-check.ts` passes.
