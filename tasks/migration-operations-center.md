# Migration Timeline → Enterprise Migration Operations Center

Refactor `/dashboard/migration-timeline` (`src/app/dashboard/migration_timeline/`) per
`Qguard_Wiki/Migration_Timeline_Refactoring`. Not cosmetic — a real SOC-style
Migration Command Center. Re-theme gold → neon cyan to match the platform.

## Architecture (no data duplication — reuse shared services)

| Concern | Shared source (already in repo) |
|---|---|
| Crypto evidence backbone (assets, CBOM, findings, history, severity, runtime) | `useScannerIntelligence()` |
| 11-stage NIST lifecycle + certification readiness + per-asset lifecycle | `useMigrationWorkflow()` → `/api/v1/migration-workflow` (30s cache) |
| Live orchestration (job phases, throughput, priority queue, agents, progress) | `useMigrationOrchestrator(true)` → `/api/v1/migration-orchestrator` + SSE stream |
| AI recommendations | `useDashboard()` recommendations (same as Executive) |
| Design system | `_components/executive/primitives.tsx` + `qg-executive-panel` glass, cyan `#22d3ee` |

All derivations are PURE functions in `_ops-lib.tsx` — turn the three snapshots into
view models. No fabricated production metrics; honest empty states where evidence is absent.

## Files
- `_ops-lib.tsx` — types, cyan tokens, pure derivations (banner/KPIs/waves/gates/timeline/twin/health/risk/assets/deps/activity/audit), small primitives.
- `_ops-sections.tsx` — section components (waves, phase gates, timeline, digital twin, live telemetry, AI recs, health, risk burndown, asset table, dependency graph, activity feed, audit trail).
- `_ops-drawer.tsx` — right-side details drawer + command palette.
- `MigrationTimeline.tsx` — container: hooks, state (filters, selection, fullscreen, palette, saved views), mandated layout order.

## Mandated layout order
Executive Banner → Mission-Control KPIs → Wave Overview → NIST Phase Gates →
Timeline → Digital Twin → Live Telemetry → AI Recommendations → Health →
Risk Burn-down → Asset Table → Dependency Graph → Activity Feed → Audit Trail.

## Cross-cutting UX
Animated counters, skeleton loading, live SSE, details drawer, command palette (Cmd/Ctrl-K),
keyboard shortcuts, multi-select + bulk actions, persistent filters + saved views, fullscreen,
CSV/JSON export, responsive, reduced-motion, accessibility.

## Verify
`npx tsc --noEmit` clean · build succeeds · route renders · empty states honest · SSE live · no gold left.

## STATUS: COMPLETE (2026-07-24)
Files: `_ops-lib.ts` (derivations), `_ops-sections.tsx` (14 sections), `_ops-drawer.tsx`
(details drawer + Cmd/Ctrl-K command palette), `MigrationTimeline.tsx` (container).
Shared edit: `_components/executive/primitives.tsx` Panel got `key?: string | number`
(repo React-19 convention, matches KpiCard; additive, never destructured).

All 22 spec sections implemented. Design re-themed gold → neon cyan (#22d3ee).
Honest, non-fabricated choices: ServiceNow/Jira NOT faked (CAB/window/rollback are
derived); Digital Twin "Run Simulation" deep-links to real Migration Sandbox; drawer
migrate/rollback shown as "Plan Preview" from target algorithm (not claimed execution).

Verification: `tsc --noEmit` = 0 errors (whole project) · `vite build` exit 0 (19.9s) ·
all 4 modules transform 200 via Vite dev. Visual/interactive render = user confirms
(page open in their browser; SPA behind Supabase auth).
