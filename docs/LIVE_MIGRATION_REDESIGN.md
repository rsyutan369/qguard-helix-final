# Live Migration Operations — Premium Redesign

`/dashboard/live-migration` (`src/app/dashboard/live_migration_ops/LiveMigrationOps.tsx`)
redesigned to an enterprise-grade, premium experience aligned with the Agent
Collector Console, Quantum Readiness and Quantum Certification surfaces — while
keeping (and proving) all real-time wiring.

## What changed

- **Visual re-theme**: the gold `#d4af37` theme (121 refs) swept to premium
  cyan glassmorphism (`#22d3ee`); `GLASS`/`INNER` panel tokens modernized to
  `rounded-2xl border-white/10 bg-white/[0.03] backdrop-blur-xl`; header
  softened from mono-uppercase-gold to the clean cyan style used across the
  redesigned modules. The whole page now reads as one system with the agent
  console and certification pages.
- **New real-time Certification Readiness band** (below the WorkflowRail):
  directly answers "are my assets remediated and am I eligible for the Quantum
  Trust Certification?" It shows the live certification-readiness ring
  (44.8% on the reference tenant), eligible/not-eligible status, the
  certification-criteria detail, and three lifecycle cells — **Quantum-Secure
  Assets** (validated/monitored), **In Remediation** (being upgraded now),
  **Tracked Assets** — plus "View Certification" and "Remediation Roadmap"
  CTAs. It is powered by `useMigrationWorkflow` (the SAME engine that drives the
  workflow rail, Quantum Readiness and the Certification page), so the number
  can never disagree across modules.

## Real-time data flow (unchanged, verified)

The page's data layer was already strong and is preserved intact:

- REST snapshot `GET /api/v1/migration/live` (+ `?planId`).
- **SSE** `GET /api/v1/migration/live/stream` → `migration-update` frames.
- **Supabase realtime** on 9 tables (migration_jobs/plans/events/execution/
  telemetry/validation_logs/execution_queues/pqc_scan_results/crypto_exposures)
  with a debounced refetch.
- Monotonic snapshot guard (never lets an older `generatedAt` overwrite newer).
- Job actions (pause/resume/retry/rollback), bulk actions, CSV/JSON export.
- The added cert band consumes `useMigrationWorkflow` (60s refresh; server
  30s per-tenant cache), keeping it in-sync with QR/Certification.

The migration jobs execute real PQC upgrades on vulnerable assets (TLS→hybrid
ML-KEM, certs→ML-DSA, key rotation, etc. — see the agent/patcher pipeline),
and the telemetry (TLS handshakes, certificate replacements, key rotations,
PQC validations) streams live so users watch assets become quantum-secure.

## Enterprise enhancement band (additive — `Live_Migration_Enhancements`)

> **Superseded 2026-10-27** — most of this band was removed; see
> "Panel reduction (2026-10-27)" at the end of this document.

Per `Qguard_Wiki/Live_Migration_Enhancements`, an additive business-outcome
band was added above the existing operations surface (nothing removed — the
header, metric cards, telemetry, jobs list, log terminal and action bar all
remain). New component: `_enhancements.tsx` (self-contained prop contracts);
all props derived in the page from the REAL live snapshot + workflow (data
honest — unmeasurable values render "—", never fabricated).

Sections added:
- **Quantum Migration Progress hero** — "Quantum Ready" ring + % migrated bar +
  migrated/remaining/ETA + 6 outcome cells (Quantum Secure / In Progress /
  Remaining / Needs Attention / Migration Speed / Est. Completion).
- **Executive Outcomes** — 10 KPIs (Assets Protected, Vulnerabilities
  Eliminated, Success Rate, Quantum Readiness, Critical Systems, Certificates
  Upgraded, Key Rotations, Audit Readiness, Compliance, Active Migrations).
- **Cryptographic Upgrade — Before → After** — real job `fromAlgo→toAlgo`
  transitions when present, else the canonical PQC upgrade paths (RSA-2048→
  ML-KEM-768, TLS 1.2→TLS 1.3 Hybrid, ECC→ML-DSA-65, SHA-1→SHA3-512,
  AES-128→AES-256-GCM) with FIPS labels and animated arrows.
- **AI Migration Advisor** — deterministic, evidence-grounded: remaining/
  findings headline, recommendation (agent-deploy vs sequence-and-schedule),
  evidence bullets, suggested maintenance window (next Saturday 02:00),
  residual-risk band (LOW/MODERATE/ELEVATED), est. effort, roadmap link.
- **The Migration Story** strip — Assets Found → Quantum Risks → Migrating →
  Upgraded → Validated → Certified.
- **Certification Progress** checklist — TLS/Certificates/Keys/Validation/
  Compatibility/Overall status from real migration telemetry + readiness bar.
- **Final Success celebration** — appears at 100% + eligible: "Enterprise
  Successfully Upgraded" + Download Certificate.

Better terminology (Active Migrations, In Progress, Needs Attention,
Successfully Protected) is used in the new sections; existing sections
untouched.

## Verification (2026-07-17)

- `tsc --noEmit` clean; `vite build` clean.
- Authenticated headless render (Elite/owner) confirmed the premium theme, the
  Certification Readiness band (44.8% / Not Yet Eligible / lifecycle cells /
  CTAs), the 4 metric cards, Real-Time Telemetry, Activity Feed, Migration Jobs,
  Migration Log terminal, and the sticky action bar — with footer showing
  **"SSE connected" + "Realtime SUBSCRIBED"**.
- Backend real-time check: `migration/live` 200 (7 telemetry keys),
  `migration-workflow` 200 (certReadiness 44.8%, 4 lifecycle stages), and the
  SSE stream emitted a live frame. No API changes.
- Access: Live Migration is a Pro+ module (Basic sees the upgrade gate) —
  unchanged.

## Panel reduction (2026-10-27)

The page was too crowded. Removed at the owner's request, together with their
page-level wiring:

| Removed panel | Wiring removed from this page |
| --- | --- |
| Post-Quantum Migration Workflow™ rail | `<WorkflowRail>` + the page's `useMigrationWorkflow()` subscription |
| Quantum Migration Progress hero | `_enhancements.tsx` (deleted) and its derived props |
| Executive Outcomes (10 KPIs) | same |
| AI Migration Advisor | same |
| Certification Progress (+ the 100% success banner, which was its end state) | same |
| Enterprise Migration Orchestrator | `_orchestration.tsx` (deleted) — the page no longer polls `/api/v1/migration-orchestrator` or opens its SSE stream |

Shared backends were **not** deleted: `/api/v1/migration-orchestrator` still
feeds Migration Timeline and PQC Orchestration, and `/api/v1/migration-workflow`
feeds the workflow rail on ~30 other pages.

Kept: header and stream indicator, planner handoff, the four job metric cards,
Real-Time Telemetry, Activity Feed, Migration Jobs, job detail, Migration Log,
Snapshot Management, the action bar and the confirmation dialog — all still fed
by `GET /api/v1/migration/live`, the `/live/stream` SSE (`migration-update`)
and Supabase realtime on the 9 migration tables.

Also corrected:

- **Cryptographic Upgrade — Before → After** (now `_crypto-upgrade.tsx`) shows
  only transitions recorded on the tenant's real, non-sandbox jobs, with a
  completed/total job count. The generic "canonical upgrade paths" fallback was
  removed, because with no jobs it read as if those transitions had been found
  in the estate; an empty state is shown instead. The FIPS label now comes from
  the target algorithm rather than a fixed string.
- The Migration Log "Live" dot was always green; it now follows the stream
  (Live / Reconnecting / Stale), like the header.
- The Real-Time Telemetry health pill was always green, even for "Degraded";
  its tone now follows the server verdict.

## Four-agent PQC Migration Workflow command center (2026-10-28)

Built per `Qguard_Wiki/Agent_Workflow_Animation`. The top of
`/dashboard/live-migration` is now a real-time **Collector → Scanner → Patcher →
Migration Operator** workflow. The job board, job detail (target algorithm,
migration type, strategy, agent status, asset type, owner, Local Config
Ownership, Connector / Operator Credentials), rollback, snapshots,
pause/resume, export and the confirmation dialog are all kept below it.

### What already existed (reused, not replaced)

| Capability | Where |
| --- | --- |
| Four agent roles + write authority | `lib/agent-installer/agent-release.ts`, `agent-scope.ts` (`resolveWriteAuthority`) |
| Agent scan frames (`connecting` … `scan_complete`) | agent runtime `reportScanStage` → `POST /agent/scan-progress` → `agent_heartbeats` (status `scan_progress`) |
| Host health telemetry (memory %, load, counters) | agent heartbeat → `scanner_agents.metadata.lastTelemetry` + `agent_heartbeats` |
| Execution class (who may run a job) | `jobExecutionClass` in `api-server/agent-scanner.ts` |
| Approval / dispatch-block / snapshot gates | `lib/migration/job-safety.ts`, `operational-workflow.ts`, agent poll |
| Agent realtime bus with sequence ids | `api-server/agent-event-bus.ts` |
| Live snapshot + SSE + Supabase realtime | `GET /api/v1/migration/live`, `/live/stream` |

### What was added

- **`src/lib/migration/agent-workflow.ts`** — pure, isomorphic model:
  per-stage status (`idle | queued | waiting | running | blocked |
  awaiting_approval | paused | retrying | completed | failed | cancelled`),
  reason, current task, measured progress (or `null` = indeterminate), units,
  fleet (enrolled / online / authorised), host metrics, outputs, findings,
  next action; edges with recorded handoff timestamps; a bounded (400),
  attributed, redacted event stream; vulnerability summary; `deriveRisks`
  (PQC Risks & Guardrails) and `safetyChecklist` (12 safeguards: Verified /
  Pending / Failed / Not applicable).
- **Snapshot** (`api-server/migration.ts`): adds `agentWorkflow`, `runs` (plan
  selector) and `workflowDegraded`. New reads are optional — a failure yields
  `null`/Unknown, never zero and never an aborted snapshot.
- **SSE** `/live/stream` now subscribes to the agent bus: `agent-event` frames
  carry the bus sequence as the SSE `id`, so a reconnect replays via
  `Last-Event-ID`; each burst triggers one debounced, single-flight snapshot
  rebuild. Payloads are redacted; delivery is tenant-filtered.
- **UI** (`live_migration_ops/_workflow-*.tsx`, `live-workflow.css`): React Flow
  canvas (pan/zoom/fit, keyboard focus, stacked cards below `lg`, screen-reader
  list + live region), GSAP-driven status/progress/check/timeline/notification
  motion, header (status, agents online, stage-weighted progress, elapsed,
  errors/warnings, Pause/Resume/Cancel, run selector, More Actions), live
  notifications (dismiss + severity preference, per browser), execution
  timeline (agent/severity/type filters, live toggle, expandable evidence),
  agent metrics, vulnerability donut, agent insights (live output JSON), logs
  (filters, search, CSV of visible lines + full server export), guardrails
  (hover highlights the affected agent) and the safety checklist.

### Truth rules

- Collector/Scanner progress is the agent's own reported stage %; a run with no
  frame for 10 min is **Blocked**, not Running. Patcher/Operator progress is
  finished jobs ÷ countable jobs. Overall = 4 × 25 % over stages that have
  measurable work; the basis names unmeasured stages.
- Handoff packets animate only when an edge's recorded `lastHandoffAt` advances
  (collector `scan_complete` frame; remediation job created; remediation
  validated) — never on page load, never on a timer.
- Sandbox simulations are excluded from agent stages (count disclosed).
- CPU is 1-min load ÷ cores as the agent reports it; Windows hosts report no
  load average, so it shows "—". API latency is this browser's measured
  round trip of the snapshot request.
- Checklist items turn Verified only from recorded evidence (approval verdict,
  `preChangeSnapshotId`, passing validation, persisted execution records…).

### Verification

- `npm run check:live-workflow` — 51 offline assertions incl. negative controls
  (idle tenant, stalled run, silent agent, sandbox exclusion, approval /
  authority gates, Windows load, checklist, guardrails, redaction, bounds).
- `npx tsx tools/rollback-check.ts` — still passes.
- `tsc --noEmit` — clean.
- Fixture harness through the real components in the browser pane: four nodes,
  model-driven edge states, packet fires only on the edge whose handoff
  advanced, status changes announced, no horizontal scroll at 375 px. (A React
  Flow edge remount bug that swallowed the packet was found and fixed here.)
- `/api/v1/migration/live` and `/live/stream` load and return 401 without a
  session.

### Known limitations

- Not yet verified against a signed-in tenant with live agents (the page is
  login-gated); `vite build` was not run (blocked by Smart App Control here).
- Collector/Scanner have no server-side pause — header Pause/Resume act on
  migration jobs; agent schedules stay in the Agent Center (the disabled
  button says so).
- The agent bus replay buffer is in-process (500 events); after a server
  restart the next snapshot reconciles state.
