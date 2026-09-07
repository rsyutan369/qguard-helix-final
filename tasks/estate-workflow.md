# /dashboard — Estate Exposure Workflow (replaces Exposure Graph + Node Inspector)

## Goal
Remove the Enterprise Quantum Exposure Graph™ and Node Inspector panels from
/dashboard and put the Exposure Workflow (the Local/Dev scanner component) in
their place — same interaction model, projecting the TENANT ESTATE instead of a
single assessment.

## The distinction that shapes everything
`/dashboard/scanner?mode=local|dev` renders ONE `ExposureAssessment`: a scan, its
lifecycle phases, the engine processes those phases spawned, and what they read.
That model does not exist at tenant level — there is no single run, no phase
tree, no engine registry. The estate has a different, equally real process
lineage:

    scan session → asset → { component, certificate, algorithm, finding } → remediation
                      └── asset relationship (parent/child, real rows)

So the RENDERER is reused unchanged and the PROJECTION is new. Synthesising a
fake `ExposureAssessment` from tenant rows would have invented phases and engine
processes that never ran — the exact fabrication the platform's data-integrity
rules forbid.

## Accuracy contract (the point of the request)
1. Every node is a projection of a row the tenant already has. The graph cannot
   contain an asset, finding, component or certificate that the Assets, CBOM and
   Findings pages do not also contain.
2. `graph.reconciliation` is rendered, and `tools/estate-workflow-check.ts`
   asserts projected == source for every entity type.
3. Risk comes from the SHARED `deriveAssetPostureModel` — the same call
   /dashboard/assets, Quantum Readiness and the Migration Planner make — so an
   asset reads the same number on every page. No private accumulator.
4. ABSENCE IS NOT SAFETY: an unassessed asset carries severity `null` ("Not
   assessed"), never `info` and never a passing colour.
5. Relationships are the real `asset_relationships` rows. No inferred topology.
6. Bounded and honest: caps per kind, with `truncation` rendered.

## Execution plan
| # | File | Change |
|---|------|--------|
| 1 | `src/lib/scanner/exposure/workflow-graph.ts` | Add `asset` + `certificate` node kinds, `assessed`/`connects`/`hosts` edge kinds, `environment` grouping. Shared vocabulary, one model. |
| 2 | `src/lib/dashboard/estate-workflow.ts` (new) | Pure, isomorphic projection: tenant rows → `WorkflowGraph`. Owns the estate lens set. |
| 3 | `src/api-server/dashboard.ts` | `GET /api/v1/dashboard/estate-workflow` — reuses the exposure-map query set so the two cannot disagree. |
| 4 | `src/hooks/use-dashboard.ts` | `estateWorkflow` state + fetch + refresh wiring. |
| 5 | `src/components/exposure/ExposureWorkflowGraph.tsx` | Accept a PRE-BUILT graph (+ lenses/findings/exposures) as an alternative to `assessment`. Four touch points; behaviour for Local/Dev unchanged. |
| 6 | `src/app/dashboard/page.tsx` | Drop `QuantumExposureMap` + `NodeInspector`; render the workflow full-width. |
| 7 | `tools/estate-workflow-check.ts` (new) | Reconciliation + absence-is-not-safety + relationship fidelity assertions. |

## Validation
- `npx tsx tools/estate-workflow-check.ts`
- `npm run lint` (tsc --noEmit) clean
- Browser: /dashboard renders the workflow, every lens, node click shows real
  facts; /dashboard/scanner local+dev unchanged.
