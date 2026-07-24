# PQC Orchestration → Enterprise Automation & Orchestration Command Center

Refactor `/dashboard/pqc-orchestration` (`src/app/dashboard/pqc-orchestration/`) per
`Qguard_Wiki/PQC_Orchestration_Refactoring`. Re-theme gold → neon cyan. NOT cosmetic.

## Architecture — reuse the SAME triad as Migration Ops Center / Live Migration Ops
| Concern | Shared source |
|---|---|
| Automation engine: workflows (priorityQueue), phases, agents, throughput, validation, assets | `useMigrationOrchestrator(true)` + SSE `orchestrator-update` |
| 13-stage global pipeline | `useMigrationWorkflow()` (11 canonical stages → 13) |
| Evidence: CBOM/assets/findings/history/severity | `useScannerIntelligence()` + SSE `scanner-intelligence` |
| AI advisor | `/api/v1/dashboard/recommendations` |

Reuse pure helpers/tokens from `../migration_timeline/_ops-lib` (formatters, classifyInventory,
buildWaves, buildDigitalTwin, buildActivityFeed, buildAuditTrail, CYAN/TONE_HEX, OpsInputs) and
UI primitives `SectionCard`/`Chip`/`AnimatedStat` from `../migration_timeline/_ops-sections` —
guarantees numeric + visual consistency across both command centers (no re-animation bug).

## Files
- `_orch-lib.ts` — orchestration derivations (workflows, kanban, DAG, console, CAB, pipeline,
  marketplace, scheduler, policies, analytics, event stream, compliance).
- `_orch-sections.tsx` — 20 section components.
- `_orch-drawer.tsx` — workflow details drawer + Cmd/Ctrl-K command palette.
- `PqcOrchestration.tsx` — container (hooks, selection, fullscreen, layout order).

## Mandated layout order
Executive Automation Summary → Automation Command Center ribbon → Global Orchestration Pipeline
→ Workflow Command Console → Digital Twin Validation → CAB Approval Center → Workflow Queue →
Execution DAG → (Details Drawer) → Live Telemetry → Automation Analytics → Kanban Task Board →
Event Stream → Automation Marketplace → Scheduler → Automation Policies → Compliance Mapping →
Audit Trail → AI Recommendations.

## Honest (no-fabrication) rules
Reuse: ServiceNow/Jira NOT faked (CAB shows real-derived + "not connected"); Digital Twin buttons
deep-link to Migration Sandbox; marketplace/policy "match counts" are REAL scanner evidence;
orchestrator-gated metrics fall back to scanner with honest basis when no jobs / not Pro.

## Verify
`tsc --noEmit` 0 errors · `vite build` · Vite transforms · route renders · light+dark · SSE live.

## STATUS: COMPLETE (2026-07-24)
Files: `_orch-lib.ts` (derivations, reuses migration `_ops-lib`), `_orch-sections.tsx` (17 orch
sections + reuses SectionCard/Chip/AnimatedStat/DigitalTwinPanel/AuditTrailPanel/AiRecommendationsPanel),
`_orch-drawer.tsx` (WorkflowDrawer + reuses CommandPalette), `PqcOrchestration.tsx` (container).
All 22 spec sections implemented. Gold → cyan. Bespoke supabase/EventSource wiring replaced by the
3 shared hooks (matches Migration Timeline + Live Migration Ops → numbers consistent by construction).
New interactive widgets: 13-stage pipeline, zoom/pan DAG (critical-path), drag-drop Kanban, workflow
queue (filter/sort/bulk/CSV+JSON), marketplace (16 templates w/ live match counts), scheduler,
IF/THEN policies (live match counts + toggle), analytics, categorized event stream, CAB center.
Verified: tsc 0 errors (whole project) · vite build exit 0 (9.75s, 3898 modules) · all 4 modules
transform 200 via Vite dev.
