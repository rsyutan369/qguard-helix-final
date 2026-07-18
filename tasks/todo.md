# Sophia Deep-Reasoning Upgrade — Deep Search / Deep Context / Consultant-grade (2026-07-18)

Spec: Qguard_Wiki/AI_Sophia_Upgrade. Screenshots show shallow single-module
summaries ("Migration is 68%") that answer WHAT not HOW/WHY. Upgrade the
reasoning engine to a CISO-grade deep-investigation pipeline: intent → objective
inference → question expansion → full cross-module search → dependency/relationship
reasoning → evidence correlation → risk → prioritized recommendations → NL
explanation. Every consultative question investigates the whole platform and
returns a structured answer (exec summary, key findings, reasoning, root cause,
business impact, technical analysis, migration strategy w/ order+rationale+
breakages, rollback, risk before→after, compliance, dependencies, proactive
findings, next questions). Evidence-driven only; no fabrication.

- [x] Contract src/types/copilot.ts — extended CopilotAnswer with optional deep
      fields (mode, objectiveKind, objective, keyFindings, rootCause,
      businessImpact, technicalAnalysis, migrationStrategy{steps:
      order+rationale+breaksIf}, dependencies, potentialBreakages,
      rollbackStrategy, riskOutlook before→after, complianceAlignment,
      proactiveFindings) + MigrationStep/ProactiveFinding/RiskOutlook/
      MigrationStrategy types + new CopilotStage values (expanding/
      investigating/correlating/analyzing).
- [x] Knowledge src/api-server/copilot-knowledge.ts — inferObjective(question)
      → {kind: guidance|prioritization|executive|gap_analysis|explain|status,
      objective, investigate} + expandQuestion() (related sub-topics).
- [x] Engine src/api-server/copilot-engine.ts — INVESTIGATION_TOOLS (20 broad
      read-only cross-module tools); planQuery unions them in investigate mode
      (cap 22, cheap via 15s cached builders) + carries mode/objective/expansion;
      extractIntelligence() correlates every tool into one TenantIntelligence;
      5 mode composers (migration guidance w/ canonical PKI-first order +
      per-step rationale + breaksIf + rollback + effort/timeline, prioritization
      w/ WHY via risk×exposure×blast×internet-facing, executive readiness verdict,
      certification gap-analysis w/ root cause, explain-risk w/ Shor/Grover);
      detectProactiveFindings (expired/expiring certs, offline collectors, failed
      jobs, no snapshot before active migration, critical blockers); composeAnswer
      branches investigate→deep synthesis (+agent enrichment) / direct→agent path;
      empty-tenant honesty (no fabricated strategy); richer streamed stages.
- [x] UI src/components/copilot/SophiaMessage.tsx — renders "Deep investigation"
      badge, objective ("What you're asking"), key findings, risk outlook
      before→after, root cause, business impact, technical analysis, numbered
      migration strategy (rationale + "if out of order" breakage per step +
      effort/timeline), dependencies, what-could-break, rollback strategy,
      proactive findings ("While investigating I also detected"). Premium
      enterprise styling; existing sections preserved.
- [x] Verify tools/copilot-check.ts — 22 sections / 97 assertions all pass
      (objective inference, deep-investigation breadth 21 tools, migration-
      guidance structure PKI-first + breakages + rollback + risk outlook +
      standards, prioritization WHY, executive/gap-analysis/explain modes,
      proactive findings, direct-mode preserved, empty-tenant honesty). tsc
      clean; vite build green (69s).
- [x] Docs: updated docs/AI_SECURITY_COPILOT.md + memory.

Rollback: additive/optional fields — old answers still render; revert the
engine/knowledge/UI edits to restore shallow behavior.

DONE 2026-07-18. Sophia now runs a full cross-module investigation and answers
HOW/WHY with a structured consultant report instead of a single-module summary.

---

# Sophia — QGuard Helix AI Security Copilot™ (2026-07-18)

Specs: Qguard_Wiki/AI_Security_CoPilot + Qguard_Wiki/AI_CoPilot_Multi-Tenant_Isolation.
Enterprise AI Security Copilot ("Sophia") available on every dashboard page:
gateway → intent detection → planner → parallel typed tools → multi-agent
reasoning → evidence-based streamed responses. Strict tenant isolation (RLS
client + explicit user_id scoping), RBAC capability matrix, audit logging,
prompt-injection protection, rate limiting. No fabricated data — every answer
derives from the tenant's live platform builders (buildSnapshot,
buildScannerIntelligence, buildExposureIntelligence, remediation/certification
engines, HNDL, workflow, migration/telemetry tables).

Plan (agents: Architect→Builder→Auditor inline; validation via check tool + tsc/build):

- [x] Contract src/types/copilot.ts (intents, agents, evidence/recommendation/
      answer schema, stream events, conversations, context, insights).
- [x] Knowledge base src/api-server/copilot-knowledge.ts (26-module registry
      with deep links, 20-intent catalog + weighted detection + follow-up
      resolution, planner map, standards catalog [NIST CSF 2.0 / SP 800-53 /
      800-57 / 800-131A / 800-208 / 1800-38 / FIPS 203-205 / CNSA 2.0 / ISO
      27001+19790 / PCI DSS / CIS v8 / OWASP ASVS / ETSI / IETF hybrid], RBAC
      role-capability matrix, prompt-injection sanitizer w/ invisible-char
      strip, page-aware suggested questions).
- [x] Tool layer src/api-server/copilot-tools.ts — 57 MCP-style typed tools
      (assets/scanner/CBOM/exposure/migration/remediation/certificates/PKI/
      harvest-now/reports/telemetry/collectors/patchers/orchestrator/
      connectors/compliance/readiness/risk/certification/snapshots/rollback/
      logs/recommendations). Reads via cached tenant builders + tenantRows
      helper that ALWAYS pins .eq('user_id') (proven by check); operate-class
      tools are guarded human-in-the-loop preflights (audit + deep link into
      owning module, never autonomous mutation). RBAC-enforced in runTool.
- [x] Engine src/api-server/copilot-engine.ts — 8 specialist agents +
      coordinator, parallel tool execution, evidence merge, deterministic
      confidence scoring (coverage×freshness), conversation memory (follow-up
      resolution), proactive insights, empty-tenant honesty guard.
- [x] Gateway src/api-server/copilot.ts → /api/v1/copilot (basic tier):
      requireAuth + role resolution (profiles.role, owner bypass) + entitlement
      tier, token-bucket rate limiting (burst+window), audit_logs writes,
      conversations CRUD + search + pin + export (Supabase copilot_* tables w/
      graceful in-memory fallback), POST /chat (JSON + SSE stage/tool/answer),
      GET /context /suggestions /insights /health.
- [x] Schema supabase/sophia-copilot-schema.sql (copilot_conversations,
      copilot_messages; RLS auth.uid() = user_id; indexes; touch trigger) —
      user applies (works in-memory until then).
- [x] Exports: harvest-now buildHndlIntelligence (existing re-export),
      migration-workflow buildWorkflowState, quantum-certification
      buildCertificationDashboard, migration-snapshots buildSnapshotDashboard.
- [x] Mount in index.ts + subscription-guard basic entry + subscription-access
      /dashboard/sophia basic.
- [x] Hook src/hooks/use-copilot.ts (context/insights/suggestions/
      conversations + POST fetch-reader SSE chat streaming + Web Speech voice).
- [x] UI src/components/copilot/ — SophiaMessage.tsx (structured answer cards:
      summary/evidence/reasoning/recommendations/risk/next actions/related
      pages/confidence meter/standards), SophiaCopilot.tsx floating dock
      mounted in DashboardLayout (all pages).
- [x] Full console src/app/dashboard/sophia/page.tsx (history sidebar +
      streaming chat center + context/insights right rail) + App.tsx route +
      Core Modules nav item.
- [x] Verify tools/copilot-check.ts 14 sections / all pass (intent detection,
      planner, 57-tool registry completeness, STRICT tenant scoping via mock
      client [39 queries/29 tools all user_id-pinned], RBAC denial matrix,
      role normalization, sanitizer, confidence bounds, evidence composition,
      empty-tenant honesty, memory follow-ups, insights ranking, rate limiter,
      suggestions). tsc --noEmit clean; vite build green (32s). LIVE: 401 on
      /copilot/health + /context + /suggestions + /chat (auth-first), 404 on
      unknown path (router confirmed mounted).
- [x] Docs docs/AI_SECURITY_COPILOT.md + memory.

Rollback plan: feature is additive — removing the copilot mounts (index.ts,
DashboardLayout widget, App.tsx route, nav item) + new files reverts cleanly;
copilot_* tables are standalone (no FK into existing tables' behavior).

DONE 2026-07-18. Both specs (AI_Security_CoPilot + AI_CoPilot_Multi-Tenant_
Isolation) fully implemented and verified — see docs/AI_SECURITY_COPILOT.md.

---

# Quantum Exposure Graph™ — Enterprise Dependency & Migration Intelligence (2026-07-18)

Spec: Qguard_Wiki/Crypto_Exposure_Graph_Enhancement. Transform
/dashboard/quantum-readiness/exposure-graph into an Enterprise Cryptographic
Dependency Graph + Migration Impact Analysis + Trust Relationship platform.

Plan (agents: Architect→Builder→Auditor inline; validation via check tool + tsc/build):

- [x] Shared pure intelligence src/lib/exposure-graph-intel.ts (isomorphic —
      backend, frontend and check tool import the SAME logic): 24-category
      classification, 12-tier migration ladder, blast-radius BFS (direct/
      indirect/trust-chain), Migration Impact Analysis™ (NIST target mapping,
      what-breaks per neighbor category, remediation, bounded risk/downtime/
      compatibility/confidence estimates), explainable composite priority.
- [x] Contract src/types/exposure-graph.ts (5-state posture incl. migrating+
      unknown, typed trust edges, third-party, waves/clusters/blockers,
      advisor, summary, EMPTY constant).
- [x] Backend src/api-server/exposure-graph.ts → /api/v1/exposure-graph (basic
      tier): reuses buildSnapshot + raw tenant rows; derives trust edges
      (relationships + cert-issuer chains [internal issuers → internal edges] +
      runtime communication paths), external nodes (CAs/vendor hosts/linked
      cloud connectors) — evidence-only. Pure assembleExposureIntelligence()
      exported. GET / + /stream (SSE 30s heartbeat 25s, header-auth only,
      exposure-intelligence frames). Per-tenant 15s single-flight cache.
      Mounted in index.ts + subscription-guard basic entry.
- [x] Hook src/hooks/use-exposure-graph.ts (fetch + header-auth ReadableStream
      SSE + Supabase realtime on the 9 evidence tables).
- [x] UI rebuild exposure-graph/: page.tsx (6-card KPI band + secondary strip +
      toolbar + fullscreen Esc overlay + evidence footer), _graph.tsx (memoized
      zoom/pan canvas, 5 group-by layouts incl. tier columns, animated trust
      flows + SMIL blast pulse + rotating migrating ring, shapes per category,
      search centering, hover tooltip, edge selection), _panels.tsx (Overview/
      Impact/Blast tabs, What-Will-Break report, edge trust metadata),
      _intelligence.tsx (waves + clusters + blockers, third-party table, risk
      prioritization table, AI advisor cards + estimates), _common.ts.
- [x] Verify: tools/exposure-graph-check.ts 64/64 (assembly, 5-state posture,
      external derivation, blast BFS, impact mapping, wave order PKI<Web,
      clusters/blockers, third-party categorisation, advisor, empty-state
      honesty). tsc clean; vite build clean. LIVE: 401 unauth / 200 owner real
      evidence (external CA node from Google Trust Services issuer, waves,
      vendor blocker, 3 recs) / SSE exposure-intelligence frames. Headless-
      Chrome (raw CDP + injected session): KPI band, canvas, node click →
      rail, Impact tab (ECDSA P-256→ML-DSA-65), honest empty state, zero
      console errors.
- [x] Docs docs/EXPOSURE_GRAPH.md + memory.

Rollback plan: page is self-contained; restoring the previous single-file
page.tsx and removing the new router/mount reverts cleanly (no schema changes).

---

# Live Migration Massive-Scale Orchestration (2026-07-17)

Spec: Qguard_Wiki/Live_Migration_Massive_ScalabilityCapable. Enterprise-scale
distributed orchestration + real-time telemetry for Live Migration.

- [x] Types src/types/migration-orchestrator.ts.
- [x] Backend src/api-server/migration-orchestrator.ts → /api/v1/migration-
      orchestrator (Pro+): pure scheduler (toOrchJob/jobPhase/planReconciliation/
      computeMetrics) — priority queues, dependency-aware blocking, lease-based
      distributed locking + idempotent claim, exponential-backoff retry,
      back-pressure/rate-limit, dead-letter isolation, node-failure recovery
      (stale-lease reclaim). State in migration_jobs.metadata.orchestration (NO
      schema change). Bounded reconciliation loop (≤60/cycle). Real metrics from
      migration_jobs/validation/agents/connectors; infra CPU/mem/latency only if
      agent reports (else null — no fabrication). GET / + GET /stream (SSE 15s).
      Mounted + Pro tier entry.
- [x] Hook src/hooks/use-migration-orchestrator.ts (fetch + header-auth SSE).
- [x] UI src/app/dashboard/live_migration_ops/_orchestration.tsx —
      OrchestrationPanel (progress bar + throughput sparkline + 10-phase
      breakdown + 6 perf tiles + priority queue + fleet health + 10
      capabilities + reconciliation feed). Added additively to the page.
- [x] Verify: tsc clean, vite build clean; tools/orchestrator-check.ts 24/24
      (phases, dependency, lease reclaim, backoff+dead-letter, back-pressure,
      priority, real metric math, null infra); live owner (Starter 403 / Pro
      200, 10 capabilities, honest null infra, SSE orchestrator-update frame).
- [x] Docs docs/LIVE_MIGRATION_SCALABILITY.md + memory.

---

# Migration Snapshot Management (2026-07-17)

Spec: Qguard_Wiki/Snapshot_Management. Pre-migration snapshots + safe rollback
for Live Migration.

- [x] Schema supabase/migration-snapshots-schema.sql (migration_snapshots +
      migration_snapshot_audit, RLS tenant-isolated, indexes, realtime).
- [x] Types src/types/migration-snapshot.ts.
- [x] Backend src/api-server/migration-snapshots.ts → /api/v1/migration-snapshots
      (Pro+): captures REAL crypto state (algorithms/TLS/PKI/certs/keys/config)
      from crypto_inventory/certificates/generated_keys/job-meta; SHA3-256
      integrity; auto pre-migration snapshots for active jobs; AUTO-ROLLBACK on
      failed jobs w/ restorable snapshot; restore (integrity-gated, drives job
      rollback) / verify / delete (retention-gated) / audit / SSE; graceful
      schemaReady:false. Mounted + tier entry in subscription-guard.
- [x] Hook src/hooks/use-migration-snapshots.ts (fetch + header-auth SSE +
      realtime + create/restore/verify/delete).
- [x] UI src/app/dashboard/live_migration_ops/_snapshots.tsx — dashboard card
      (Total/Restorable/Auto+Manual Rollbacks/Storage/Integrity/Latest) +
      management drawer (list/search/filter/compare/download/restore/verify/
      delete + Audit Log tab). Snapshots button beside Rollback in toolbar;
      Rollback opens the snapshot restore drawer focused on the job's asset.
- [x] Verify: tsc clean, vite build clean; tier gating (Starter 403 / Pro 200
      schemaReady:false) live; tools/snapshot-check.ts 16/16 (capture,
      deterministic SHA3-256, tamper detection, empty state); authed render of
      the drawer + toolbar Snapshots button + setup notice.
- [x] Docs docs/MIGRATION_SNAPSHOTS.md + memory.
- [ ] USER: run supabase/migration-snapshots-schema.sql in the Supabase SQL
      Editor (idempotent); snapshots then capture automatically on migration.

---

# Live Migration Enhancements — additive band (2026-07-17)

Spec: Qguard_Wiki/Live_Migration_Enhancements. ADD business-outcome
enhancements (Before→After, AI Advisor, etc.) WITHOUT redesigning the page.

- [x] New src/app/dashboard/live_migration_ops/_enhancements.tsx (self-contained
      prop contracts). Page derives ALL props from real snapshot+workflow
      (data-honest; unmeasurable = "—").
- [x] Added band above existing operations surface (nothing removed):
      Quantum Migration Progress hero (ring + %migrated + 6 cells), Executive
      Outcomes (10 KPIs), Cryptographic Upgrade Before→After (real job
      transitions else canonical PQC paths, animated), AI Migration Advisor
      (deterministic: headline/rec/evidence/window/residual-risk/effort),
      Migration Story strip, Certification Progress checklist, Final Success
      celebration (100%+eligible → Download Certificate).
- [x] Verify: tsc clean, vite build clean; authed CDP render (owner) shows all
      sections with real values (44.8% readiness, 38 findings, 8 critical, Sat
      Jul 18 02:00 window, ELEVATED residual, ≈1.9h effort); footer "SSE
      connected / Realtime SUBSCRIBED" — existing real-time wiring intact.
- [x] Docs: docs/LIVE_MIGRATION_REDESIGN.md updated + memory.

---

# Live Migration Operations — Premium Redesign (2026-07-17)

Make /dashboard/live-migration enterprise/premium; real-time wired; aligned
with agents/assets/cbom/QR/certification so users see remediation→cert status.

- [x] Re-theme: gold #d4af37 (121 refs) → premium cyan #22d3ee glassmorphism;
      GLASS/INNER tokens → rounded-2xl border-white/10 bg-white/[0.03]
      backdrop-blur; header softened to clean cyan (aligned w/ agent console).
- [x] NEW real-time Certification Readiness band (useMigrationWorkflow — same
      engine as workflow rail/QR/cert): readiness ring + eligible status +
      criteria detail + Quantum-Secure / In-Remediation / Tracked asset cells
      + View Certification & Remediation Roadmap CTAs. Answers "remediated?
      eligible for cert?" in-sync across modules.
- [x] Preserved ALL real-time wiring: REST /migration/live + SSE
      /migration/live/stream + Supabase realtime (9 tables) + monotonic guard
      + job/bulk actions + export. No API/backend changes.
- [x] Verify: tsc clean, vite build clean; authed CDP render (owner) premium
      theme + cert band + telemetry + "SSE connected / Realtime SUBSCRIBED";
      backend RT check migration/live 200 + migration-workflow 44.8% + SSE
      live frame emitted.
- [x] Docs: docs/LIVE_MIGRATION_REDESIGN.md + memory.

---

# Scanner Settings Tab — Aligned Redesign (2026-07-17)

Redesign scanner ?tab=settings to complement the new Agent Collector Console;
ensure aligned/wired/hooks/SSE.

- [x] src/components/agent-collector/AgentSettingsConsole.tsx — SHARES the
      useAgentCollector hook (same REST + agent-scanner-sync SSE) so state/sync
      stay consistent with the agents console. Collector Policy editor
      (enabled/heartbeat/threshold/16-option Scan Scope grid/targets/paths,
      apply to selected|all active via PUT /agents/{id}/policy), Selected
      Collector panel (+rotate/revoke/delete + one-time token), Live Sync &
      Alerts, Security Standards (mandatory PQC stack), collapsible API refs.
      Glassmorphism matching AgentCollectorConsole.
- [x] Replaced ~24KB inline gold-themed settings block in ScannerDashboard.tsx
      with <AgentSettingsConsole/> (Pro+/owner gated, else upgrade notice).
- [x] Removed ScannerDashboard's now-redundant fetchAgents call + duplicate
      agent-scanner SSE EventSource effect (both consoles own it via the hook
      → exactly one collector SSE per tab).
- [x] Verify: tsc clean, vite build clean; authed CDP render (owner) confirmed
      (Collector Settings + policy editor + scan scope + live sync "Connected");
      backend PUT-policy path verified E2E (enroll→PUT interval=30/threshold=
      high/5 scanTypes/2 targets persisted→delete). No API changes.
- [x] Docs: docs/AGENT_COLLECTOR_CONSOLE.md updated + memory.

---

# Agent Collector Console — Enterprise UX Redesign (2026-07-17)

Spec: Qguard_Wiki/Agents_Refactor_Improvements. Redesign the Agent Collector
Scanner (scanner ?tab=agents) into a modern progressive-disclosure enterprise
console — 5-min collector deploy — preserving ALL backend capability.

- [x] Data hook src/hooks/use-agent-collector.ts — wraps existing
      /api/v1/agent-scanner/* REST + agent-scanner-sync SSE (ZERO backend
      changes); create/rotate/revoke/delete/updatePolicy/createConnector/
      createOperatorAction/setOperatorStatus/ack/resolve + evidence-derived
      summary + health/status/connection helpers.
- [x] Console src/components/agent-collector/AgentCollectorConsole.tsx —
      sub-nav (Overview/Collectors/Scans/Operations/Settings/Help); 6 summary
      cards; 4-step Quick Start wizard (Create→Install→Verify→Scan) with
      simplified form (name/env/desc/tags/targets only), one-time token +
      install tabs (Linux/Windows/Docker/K8s/Helm/PowerShell/Cloud-Init),
      verify panel; simplified collectors table + details drawer (health,
      findings, telemetry, start-scan, rotate/revoke/delete sticky bar);
      Operations Center (+ collapsible Advanced Settings); Settings→Security
      Standards (mandatory PQC stack moved off collector page); Help→How
      Collectors Work (arch diagram + FAQ). Glassmorphism, skeletons, WCAG
      (aria-current/dialog/modal, focus mgmt, ESC, focus-visible, icon+text).
- [x] Replaced ~63KB inline agents JSX in ScannerDashboard.tsx with
      <AgentCollectorConsole/> + removed dead install-command/workflow consts.
- [x] Verify: tsc clean, vite build clean; authed CDP render (owner) of
      Overview + wizard + Help confirmed; backend smoke test all 10
      agent-scanner endpoints 200 incl enroll→rotate→revoke→delete one-time
      token (no API changes).
- [x] Docs: docs/AGENT_COLLECTOR_CONSOLE.md + memory.

---

# Architecture & Scalability Review (2026-07-17)

Spec: Qguard_Wiki/Architechture_Review_Scalability-Validation. Full-platform
assessment → docs/ARCHITECTURE_SCALABILITY_REVIEW.md (verdict, tier analysis,
tenancy, asset-type coverage, real-time consistency, honest roadmap).

- [x] Review: bounded-detail/exact-headline design confirmed (row caps +
      HEAD counts + capped engine payloads); RLS tenant isolation audited;
      asset-type coverage is generic (classifyDomain/playbooks/scanner
      modules/agents), not qguardhelix-specific.
- [x] FIX #1 (the fan-out bottleneck): per-tenant single-flight 15s-TTL
      shared-computation caches for buildScannerIntelligence (bypassed during
      active scans) + buildSnapshot → all modules derive from ONE
      authoritative computation per window (the guide's shared-model
      recommendation). Measured: QR 9.2s→0.5s, remediation 5.2s→1.5s,
      scanner intel →0.7s warm.
- [x] FIX #2: supabase/scale-indexes.sql — composite (user_id, order-col)
      + status/partial-count indexes for all hot tables (idempotent,
      table-guarded).
- [x] Verify: tsc clean, remediation-check 46/46, live remediation checks
      pass post-restructure, 6-endpoint latency probe all 200.
- [ ] USER: run supabase/scale-indexes.sql once in the Supabase SQL Editor.
- [ ] Roadmap (documented): org-level tenancy, Redis/queue for multi-node,
      durable scan job queue, event-driven cache invalidation.

---

# Enhance Quantum Remediation & Migration Workflow (2026-07-16)

Spec: Qguard_Wiki/Enhance_Quantum_Remediation_Migration_Workflow. Make all 10
workflow modules act as ONE state-driven lifecycle (the guide's Additional
Recommendation): Discovery → CBOM → Assessment → Risk → Remediation →
Planning → Approval → Execution → Validation → Monitoring → Certification.

## Review findings (all 10 modules inspected — mature, reuse them)
- Remediation command center: built (Q-REMEDY). Assets 878L, CBOM 1270L,
  CryptoAgility 789L, HarvestNow 791L, LiveMigrationOps 1321L, Scanner 4950L,
  MigrationPlanner 745L (+migration-planner.ts 9-stage model), RiskAnalysis 246L.
- GAPS: (1) no cross-module workflow state layer — the core ask; (2) planner
  has an 'approve' STAGE but no approval ACTION (no endpoint/UI; migration_plans
  has id/status/metadata → zero new tables needed); (3) risk-analysis has no
  heat map; (4) assets page lacks migration/validation/cert-impact lifecycle
  columns; (5) remediation page lacks an automation-opportunities rollup CTA
  to live migration.

## Plan
- [x] Workflow engine: src/types/migration-workflow.ts +
      src/api-server/migration-workflow.ts (GET /api/v1/migration-workflow,
      30s per-user cache; reuses assembleEvidence+buildRemediationPlan (export
      assembleEvidence) + migration_plans/jobs/validation_logs +
      quantum_trust_certificates → 11 evidence-derived stages, per-asset
      lifecycle states, overall progress, next-best-action). Mount + basic tier.
- [x] Shared UI: src/components/workflow/WorkflowRail.tsx (compact stepper,
      dark/adaptive tone, active-stage highlight, next-action chip,
      click-through) + src/hooks/use-migration-workflow.ts (fetch + 60s
      refresh, hides on error).
- [x] Embed rail in all 10 pages: remediation, risk-analysis, migration
      planner, live-migration, scanner, assets, cbom, crypto-agility,
      harvest-now, quantum-certification.
- [x] Approval workflow: GET/POST /api/v1/migration-planner/plans +
      POST /plans/:id/approval (approve/reject w/ reason, approver stamped in
      metadata) + ApprovalWorkflowPanel in MigrationPlanner.tsx. ROOT-CAUSE
      FIX: migration_plans has NO name column — the old select('id, name, …')
      silently errored in safeRows so the Approve stage never saw plans;
      display name now lives in metadata.name.
- [x] Risk heat map: top exposure-graph assets × 4 risk dimensions in
      risk-analysis (every cell hover shows evidence basis).
- [x] Assets lifecycle column: workflow assetStates merged by name (stage chip
      + open actions/validation status + certification impact).
- [x] Remediation automation rollup: automatable-actions banner + Live
      Migration Ops CTA.
- [x] Deep-link fixes: runtime-crypto-intel / vendor-pqc-readiness /
      qkms/overview (remediation playbooks pointed at nonexistent routes).
- [x] Verify: tsc clean, vite build clean, remediation-check 46/46,
      workflow-live-check 12/12 (11 canonical stages, cached call <1s,
      approval round-trip submit→approve→list, invalid decision 400); authed
      headless-Chrome screenshots verified planner (rail + approval panel,
      Approve stage now Complete), assets (adaptive rail + MIGRATING lifecycle
      chip), risk-analysis (rail + live heat map).
- [x] Docs: docs/MIGRATION_WORKFLOW.md + todo/memory updates.

---

# Intelligent Quantum Remediation & Certification Engine (2026-07-16)

Spec: Qguard_Wiki/Intelligent_Quantum_Remediation&Certification_Engine.
Transform "Not Quantum Ready" into "Here's exactly how to become Quantum
Ready": per-asset AI remediation roadmap + live Certification Readiness Score
that projects the score after each recommendation, wired into the existing
certification eligibility engine.

## Reuse map (platform analysis — DO NOT duplicate)
- Evidence: buildSnapshot (quantum-readiness.ts) + buildScannerIntelligence
  (scanner.ts findings carry algorithm/category/location/threat/recommendation)
  + gatherEvidence/evaluateEligibility/DEFAULT_POLICY (quantum-certification.ts
  — the 10 required criteria ARE the certification requirements).
- Report model: buildReportModel (waves, assetReadiness, readinessProgression,
  dependencyAnalysis, confidence) — advisors already reuse it.
- Frontend: QR _shared.tsx primitives + hook patterns (header-auth SSE fetch,
  Supabase realtime); migration handoff (_advisor.ts) for deep links.
- Integration routes: Migration Planner / Sandbox / CBOM / Scanner /
  Harvest Now / PKI Visibility / Crypto Agility — link, don't rebuild.
- No new DB tables: action status derives from live evidence (finding present
  = open; gone after rescan = resolved) + real migration_jobs rows. Honest,
  auto-updating, zero schema for the user to apply.

## Advanced algorithm — Q-REMEDY (Quantum Remediation & Eligibility
## Marginal-gain Yield) — deterministic, evidence-driven
1. Normalize per-asset vulnerabilities (scanner findings + CBOM + certs).
2. Classify remediation domain (TLS/SSH/VPN/PKI/keys/app-lib/cloud/data/vendor)
   → NIST FIPS 203/204/205 + CNSA 2.0 aligned playbook (steps, hybrid target,
   effort & downtime model, rollback, breaking-change warnings).
3. Multi-factor priority score: severity, internet exposure, business
   criticality, data sensitivity, HNDL relevance, blast radius (relationship
   degree), compliance hits, certification impact → Critical/High/Medium/Low
   queues + quick wins (impact/effort leverage).
4. Certification Readiness Score: continuous 0-100% progress across the 10
   required criteria (ratio-to-threshold per criterion, equal weights,
   documented) — 100% == eligible.
5. Marginal-gain greedy simulation: each action carries measure deltas
   (criticalResolved, vulnerableComponentsResolved, pqcAdded, disallowed
   retired, certs renewed); re-run the score model per step → projection
   ladder "62% → after #1 68% → ... → 100% Certification Eligible".

## Plan
- [x] Types: src/types/quantum-remediation.ts (plan contract).
- [x] Backend: src/api-server/quantum-remediation.ts — pure engine
      (buildRemediationPlan + computeCertificationReadiness + applyImpact
      simulation, exported for tools) + Express router GET / + GET /stream
      (header-auth SSE). Exported gatherEvidence/loadPolicy from
      quantum-certification.ts for reuse.
- [x] Mount /api/v1/quantum-remediation in index.ts + basic tier in
      subscription-guard.ts (frontend /dashboard/quantum-readiness prefix
      already covers the page).
- [x] Hook: src/hooks/use-quantum-remediation.ts (fetch + SSE + realtime on
      pqc_scan_results/crypto_inventory/certificates/migration_jobs/assets).
- [x] Page: src/app/dashboard/quantum-readiness/remediation/page.tsx —
      Quantum Remediation Center (hero score + ladder + requirements +
      priority queues + asset drill-down + blast radius/vendor impact +
      quick wins/blockers + progress/recently-fixed + AI Quantum Advisor Q&A
      + integration links + methodology).
- [x] Wire: App.tsx route, QR_PAGES subnav, hub MODULES card, DashboardLayout
      nav, certification page CTA when not eligible.
- [x] Verify: tools/remediation-check.ts 46/46 offline checks pass (ladder
      monotonic, 100% == eligible, priority invariants, playbook coverage,
      FIPS terminology guard) + tsc clean + vite build clean +
      tools/remediation-live-check.ts live pass (real tenant 44.9% → ladder
      to 97.2%, Starter 403 / Basic 200, SSE frame received).
- [x] Docs: docs/QUANTUM_REMEDIATION.md + memory update.
- [ ] USER: restart `npm run dev` (the Vite-mounted Express app only picks up
      the new /api/v1/quantum-remediation route on server start), then open
      /dashboard/quantum-readiness/remediation.

---

# Revenue Intelligence Dashboard — owner-only module (2026-07-15)

Spec: Qguard_Wiki/Revenue_Intelligence_Dashboard + sample screenshot. Owner-only
executive revenue/subscription/customer/payment analytics over the REAL billing
tables (billing_subscriptions/invoices/notifications/audit + webhook ledgers).

## Reuse map (discovered)
- Owner gating: admin.ts requireOwner pattern (isOwnerEmail + query-token SSE).
- SSE: admin /stream pattern (push every 10s + heartbeat 30s).
- Frontend module pattern: quantum-readiness/_shared.tsx (snapshot contract,
  Panel/MetricCard/Donut/BarList primitives — IMPORT the generic ones), hook w/
  fetch+SSE+realtime, Shell w/ subnav. Charts: echarts-for-react (installed).
- Sidebar: NAV_SECTIONS in DashboardLayout + owner-only injection (mirrors the
  Owner Administrator injection); routes in App.tsx under /dashboard.
- Pricing: PLAN_PRICING (paypal.ts) for MRR normalization.

## Data honesty (CLAUDE.md): NO fabricated metrics
- Geography, CAC/burn/EBITDA, DAU/sessions, Stripe: no data sources exist →
  honest empty states with integration guidance, never simulated numbers.
- Forecast: deterministic linear trend of ACTUAL monthly net revenue,
  methodology stated on-page.

## Plan
- [x] Backend src/api-server/revenue.ts (mount /api/v1/revenue, owner-gated):
      GET /snapshot (revenue math incl MRR/ARR/ARPU/LTV/churn/growth, timeline,
      by plan/provider/cycle, payment stats, subscriber+invoice+customer lists,
      activity feed, alerts, health score, forecast), GET /stream (SSE),
      GET /export (csv|json per report).
- [x] Frontend src/app/dashboard/revenue-intelligence/: _shared.tsx (types,
      EMPTY snapshot, useRevenueIntelligence hook w/ SSE + billing realtime,
      RevenueShell + subnav, echarts theme helpers) + 6 pages: Overview
      (executive command center), revenue/, subscriptions/, customers/,
      payments/, forecast/ (incl. Report Center exports + notifications).
- [x] Sidebar: owner-only 'Revenue Intelligence' section directly below System
      (Owner Administrator); App.tsx routes.
- [x] Verify: tsc --noEmit 0 errors; vite build clean.
- [x] Docs: docs update + memory.
- [ ] USER: open /dashboard/revenue-intelligence as owner; data appears once
      billing tables hold real rows (subscriptions/invoices from live payments).

---

# QGuard Messaging paywall — Android + Desktop, account-based (2026-07-15)

Spec: Qguard_Wiki/Android_Paywall_Guidelines. STARTER (or higher) unlocks the
messaging app; subscription belongs to the ACCOUNT (billing_subscriptions in
Supabase = single source of truth, already realtime-published + RLS-scoped).

## Discovered architecture (reuse, don't duplicate)
- billing_subscriptions / billing_invoices / billing_notifications /
  billing_audit_events + paypal_webhook_events already exist (supabase/*.sql).
- PayPal backend complete at api.qguard.dev: /api/v1/paypal/subscribe (Bearer),
  verified webhook w/ idempotency+retry, /api/v1/billing/subscription/actions
  (upgrade/cancel/reactivate...). Messaging CSP already allows api.qguard.dev.
- Access statuses: active|trial|pending_renewal (src/lib/subscription-access.ts).
- Messaging app: no router — Page union + data.modules drive Sidebar/MobileShell.
- Android JNI pattern proven in src-tauri/src/security/keystore.rs.

## Plan
- [x] DB: supabase/play-billing-migration.sql — play_webhook_events ledger,
      provider notes. qguard-messaging migration 030 — qguard_has_messaging_access()
      + RESTRICTIVE INSERT policies on messaging_message_envelopes /
      messaging_conversations / messaging_call_signals (server-side anti-spoof:
      client can't send/call without an active plan even with a hacked UI).
- [x] Backend: src/api-server/play-billing.ts — GET /config, POST /verify
      (Google Play Developer API subscriptionsv2, service-account JWT, account
      binding via obfuscatedExternalAccountId, token-reuse rejection, acknowledge,
      upsert billing_subscriptions provider=google_play + invoices + audit),
      POST /rtdn (Pub/Sub push, secret token, RENEWED/CANCELED/EXPIRED/ON_HOLD/
      GRACE/REVOKED handling). Mounted in index.ts.
- [x] Messaging lib: subscription.ts (statuses, grace, plan catalog, API origin)
      + use-subscription.ts (fetch + billing_subscriptions realtime + period-end
      timer → instant cross-device lock/unlock) + vitest tests.
- [x] Messaging UI: SubscriptionPage.tsx (status card, plan, renewal, provider,
      invoice history, subscribe Starter→Elite via PayPal / Play Billing,
      restore purchases, cancel/reactivate, upgrade) + PaywallGate in App.tsx
      (no active sub → only Subscription + Settings + sign-out; premium pages
      never mount) + "subscription" Page + Sidebar/MobileShell entry.
- [x] Android: Kotlin PlayBilling.kt (BillingClient 7, purchase flow +
      queryPurchases restore + state JSON) + gradle dep + Rust
      commands/billing.rs (async, JNI on Android, graceful desktop stub)
      registered in lib.rs.
- [x] Verify: messaging vitest ALL passed (34/34), tsc+vite build clean, cargo
      check clean (desktop host).
- [x] Docs: qguard-messaging/docs/PAYWALL.md (setup: Play Console products,
      service account, RTDN topic, env vars; flows; testing matrix).
- [ ] USER: run the 2 SQL files in Supabase; set Play/PayPal env on the API
      deployment; create Play subscription products; E2E purchase tests.

---

# Video Call blurred media — Desktop ↔ Android emulator (2026-07-15)

Spec: Qguard_Wiki/VideoCall_Fix_Guidelines. Symptom (test_images/Video Call
blurred Images2.png): gray macroblocked smear on desktop remote view, blocky
thumbnails on Android — classic ultra-low encode resolution + collapsed bitrate.

## Root causes (evidence in code, cited per file)
1. Capture/encoder ceilings below HD — call-quality.ts `auto` = 960×540 max @
   1.2 Mbps ceiling; fullscreen desktop render of 540p is always soft. Spec
   demands 720p min / 1080p HD @ 30fps.
2. ALL WebRTC hardware video accel disabled on Windows (lib.rs
   `--disable-accelerated-video-decode/encode` etc. at every launch) → all
   encode+decode on CPU. Test topology = desktop app + Android emulator +
   emulator WebView + per-frame AES-GCM ALL on one laptop → CPU overuse →
   Chromium quality scaler collapses encoded resolution (macroblocks).
   The confirmed GPU-driver wedge was the CAPTURE path (comment in lib.rs:
   "Disabling encode/decode alone was NOT enough"), so encode/decode disables
   are moveable to the gpu-safe-mode tier without reopening the freeze.
3. Codec left to SDP default while call-frame-crypto.ts hard-codes the VP8
   unencrypted-header convention (10/3/1 bytes) — a codec drift to
   VP9/H264/AV1 would corrupt the E2EE path. Must pin VP8 explicitly.
4. Possible congested free TURN relay (openrelay.metered.ca fallback in
   call-ice.ts) carrying same-laptop calls when srflx hairpin fails →
   collapsed bandwidth estimate. Needs per-call route visibility to confirm.
5. Zero diagnostics: no getStats anywhere (grep proved) — spec §7/§8 require
   resolution/fps/bitrate/RTT/loss/route/limitation logging.
6. No contentHint on tracks, Opus left at default ~32kbps, no audio maxBitrate.
7. Quality tier resets to Auto every call (not persisted).

## Fix plan
- [x] call-quality.ts: tiers → auto 1280×720@30 / 2.5 Mbps, hd 1920×1080@30 /
      4.5 Mbps, low unchanged; per-tier audio maxBitrate (24/64/96 kbps);
      contentHint helper; localStorage persistence; sender params also tune
      audio + networkPriority.
- [x] call-stats.ts (new): pure `summarizeCallStats` + 2s getStats monitor —
      route (direct/relay), codec, out/in resolution+fps+bitrate, RTT, jitter,
      loss, qualityLimitationReason; structured console logs.
- [x] use-secure-call.ts: pin VP8 (+rtx/red/ulpfec) via setCodecPreferences;
      apply contentHints; persist quality; run stats monitor while connected;
      re-apply sender params on `connected`.
- [x] InCallOverlay.tsx + CallProvider.tsx: live stats chip + expandable
      diagnostics panel (route, res, fps, bitrate, RTT, limitation warning).
- [x] lib.rs: default launch keeps ONLY capture-path safety flags; move
      encode/decode disables + --disable-gpu under gpu-safe-mode (watchdog
      unchanged, self-heals after a mid-call crash exactly as before).
- [x] Tests: call-quality.test.ts (tier invariants incl. 720p floor),
      call-stats.test.ts (summarizer on synthetic reports).
- [x] Verify: vitest 26/26 passed (9 new), tsc + vite build clean, cargo check
      clean, cargo test commands::calls 5/5 (watchdog semantics unchanged).
- [x] Report: qguard-messaging/docs/VIDEO_CALL_QUALITY.md.
- [ ] USER E2E: rebuild desktop + Android, re-test Desktop ↔ emulator call,
      confirm stats chip shows Direct route + ≥720p once CPU settles.

---

# Secure Chat Android — open-conversation bounce (2026-07-12)

## Root cause (verified on emulator with 2 test accounts + DB forensics)
Investigation ruled OUT the suspected causes and pinned the real one:
- Android DOES register a messaging_device + prekeys correctly (proved: a fresh
  Android login for a new account produced a healthy device — 1 active signed
  prekey + 24 one-time prekeys). Search, RLS, and conversation INSERT all work
  (a real 2-party conversation was created when messaging a keyed recipient).
- REAL BUG = React state race in SecureChatPage. `startPrivateChat`/`openConversation`
  set `activeConversationId` to the just-created conversation, but the parent
  `conversations` prop only updates after an async refresh + realtime round trip.
  The "keep a valid selection" effect saw the new id was absent from the (stale)
  visible list and reset `activeConversationId` to `visibleConversations[0]` (the
  self-only starter conversation), stranding the user on the wrong thread ("Open
  a contact chat before sending", stuck "Loading encrypted history…") — or, for a
  recipient with no published keys, `startPrivateChat` early-returned AFTER
  `closeNewChat()` already closed the modal, so the tap silently dropped back to
  the list = the reported "returns to Search Users" bounce.

## Fix (src/pages/SecureChatPage.tsx)
- [x] Optimistic conversation overlay: `pendingConversations` state merged into
      `effectiveConversations`; a freshly created conversation (with real
      member_user_ids so the recipient resolves and sending works) is visible
      instantly, then pruned when the server row lands.
- [x] Reset effect made overlay-aware: only recovers a fallback selection when the
      current conversation has TRULY vanished from the full set — never because
      it is view-filtered or still settling in the overlay.
- [x] `startPrivateChat` returns a success boolean; `startChatWithUser` closes the
      New Chat modal ONLY on success. Every failure path sets a visible, honest
      `contactAction` (updated copy: keys publish on desktop OR Android) — no
      silent close/bounce.
- [x] Breadcrumb logging (`logChatFlow`) on user-select / create / open / error,
      visible in `adb logcat` (webview console) so a failed open is never silent.
- [x] Verified: tsc + vite build clean.
- [x] Rebuilt x86_64 debug APK + emulator E2E (2 confirmed test accounts, since
      cleaned up): New Chat → teslagreat101 opens the CORRECT thread ("Ready",
      "Private channel with teslagreat101"), history resolves, and a real message
      sent ("Verified · Replay-safe"). Reopen-from-list also correct. No bounce.
- [ ] Follow-up: rebuild arm64 release APK for real devices (x86_64 emulator only
      so far). Side note: hard process-kill returns app to login (session
      persistence) — separate from this bug.

## Manual test cases
1. Open existing conversation: tap a conversation in the list → thread opens to
   that exact conversation (no self-only swap), history loads.
2. Create new conversation (keyed recipient): New Chat → search → Message → thread
   opens to the NEW conversation, "E2EE active", compose enabled, send delivers.
3. Device-less recipient: New Chat → search someone with no device → Message →
   modal STAYS open with a clear "hasn't set up a device yet" message (no bounce).
4. Navigation after app restart: relaunch, unlock chat PIN, open a conversation.
5. Offline/reconnect: lose network mid-open → clear error; on reconnect, retry works.

---

# Quantum Vault on Android — content:// URI support (2026-07-12)

## Root cause (test_images/android_error2.png)
1. Android SAF pickers (dialog plugin 2.7.1) return `content://` URIs, but every
   vault command does `std::fs`/`File::open` on the raw string → "No such file or
   directory (os error 2)" on encrypt source + decrypt source.
2. `tauri-plugin-dialog` has NO mobile folder picker ("Folder picker is not
   implemented on mobile") → folder encrypt/decrypt cannot work on Android.
3. Names derive from URI basename → "Decrypting msf%3A33" instead of the filename.

## Done
- [x] New `src-tauri/src/security/content_uri.rs`: JNI ContentResolver bridge
      (openFileDescriptor → detached fd → std::fs::File; DISPLAY_NAME/SIZE query),
      desktop stubs. Reuses keystore.rs JNI pattern (jni + ndk-context).
- [x] vault.rs: `open_vault_source` (content-aware read), `VaultDest` (native
      tmp+rename vs direct SAF fd write + truncate-on-abort), content-aware
      name/size in encrypt. Converted file encrypt/decrypt/verify + recovery/
      enterprise decrypt; rewrap rejects content URIs (in-place temp+rename).
- [x] New commands `vault_resolve_name` (async — provider query off main thread)
      + `vault_default_encrypt_dest` (Android encrypt dest = app-private
      data_dir/vault/files/<name>.qvault so registry paths stay durable).
- [x] QuantumVaultPage.tsx: resolved display names in logs/suggestions (no more
      msf%3A33), Android skips save dialog on encrypt, folder buttons hidden on
      Android + handler guards, re-protect uses registry paths on Android.
- [x] Verified: host cargo check + unit tests (uri_tail/percent-decode), tsc +
      vite build, x86_64-linux-android cargo build via tauri CLI (caught E0499
      borrow errors host check missed), gradle assembleX86_64Debug, installed on
      emulator — app boots clean, no native errors in logcat.
- [ ] PENDING USER: on-device encrypt/decrypt round-trip needs login + workspace
      PIN (only the user has them). Test file staged at
      /sdcard/Download/qguard-vault-test.txt on emulator-5554.
- [ ] After user confirms: rebuild arm64 release APK with the fix.

---

# /pqc-solutions marketing page (2026-07-10)

## Done
- [x] New public marketing page `src/pages/PqcSolutions.tsx` + route `/pqc-solutions` in
      App.tsx (top-level, alongside the other four solution pages).
- [x] Maps all six Problems_To_Solve_1..6 to platform capabilities per
      Qguard_Wiki/Problem_Solution_Traceability.md (Trust-State Discovery, Migration Gate,
      TLS Trust Path Cost, Scanner/Shadow Crypto + Shor-vs-Grover threat model, QKMS,
      Readiness/Planner/Sandbox/Crypto Agility).
- [x] Reuses SolutionLayout + messaging/QR atoms from `_solution-shared.tsx` (violet lead
      accent). Signature: dark "PROBLEM_LEDGER" hero console (override-proof `bg-[#0b1322]`
      rows — NOT `bg-white/*`, which the `--light` sheet lightens). Pattern strip uses the
      matched visibility/ownership/dependencies/risk/migration_gate PNG set.
- [x] Verify: tsc clean; vite build clean; headless-Chrome screenshots of full page (hero
      console pixel-checked #0b1322; all 9 sections render; 500px-wide layout wraps cleanly).
      Note: headless `--window-size=390` screenshots look clipped because new headless clamps
      the window to ~500px min — sibling pages show the identical artifact; not a page bug.

---

# Master Implementations — Problems_To_Solve_1..6 completion pass (2026-07-10)

## Audit results (platform-wide)
- All ~70 dashboard pages verified WIRED to real backends (mode-driven shared dashboards +
  hooks + scanner intelligence). No fabricated fallbacks found in hooks.
- P1/P2 (trust estate, Visibility→Ownership→Dependencies→Risk→Migration Gate):
  trust-state-discovery.ts derives findings/gate/graph from 16 real tables — COMPLETE.
  ecosystem-supply-chain.ts (dependency map/trust chain/vendor readiness/hybrid lab)
  queries 14 real tables — COMPLETE.
- P5 (key lifecycle): qkms-dashboard.ts on real qkms_keys/rotation/policies/audit — COMPLETE.
- P6 (roadmap/agility): QR engine + migration planner + /dashboard/crypto-agility — COMPLETE.
- Removed orphan empty dir src/app/dashboard/runtime-discovery (referenced nowhere).

## Gaps implemented (all verified 2026-07-10)
- [x] P4: Shor/Grover threat-model decomposition — `threatClassFor` + `threatModel`
      snapshot block in quantum-risk-scoring.ts (Shor-exposed public-key / Grover
      symmetric margin / legacy hash / PQC-protected, each with findings, affected
      assets, share, 7d trend, top assets, urgency + roadmap guidance) and the
      "Quantum Threat Model" section with ThreatModelPanel on the page (defensive
      deep-merge in the hook).
- [x] P3: Trust Path Cost — `trustPathCost` block in tls-telemetry.ts (RTT profile
      from TLS versions, key-exchange compute classes, costliest observed paths as
      relative 0-100 index incl. retry cost, hybrid ML-KEM-768 FIPS-203
      bytes-on-wire outlook, methodology caption) + "Trust Path Cost" section with
      TrustPathCostPanel on the TLS Telemetry page. No fabricated latency.
- [x] Traceability report: Qguard_Wiki/Problem_Solution_Traceability.md.
- [x] Verified: root `tsc --noEmit` exit 0; `vite build` exit 0 (1m 5s).
- [x] RUNTIME verified (live dev server, authenticated tenant, real scan data):
      tools/threat-model-cost-check.ts — 20/20 checks on empty AND populated
      tenants (34 Shor-exposed findings from a real badssl scan → "migrate";
      cost index 100 on the legacy TLS path; RTT profile sums to
      totalConnections; hybrid outlook arithmetic exact). Starter tier 403 /
      Elite 200 confirmed the subscription gateway. Test account restored to
      canonical Starter tier afterwards.

---

# Forward Secrecy "Awaiting prekey material" — permanent fix

## Root causes (verified by code trace)
1. **One-time prekeys are never regenerated.** `ensure_identity` (state.rs) generates 24 once
   per device lifetime; `keys_upload_one_time_prekeys` (keys.rs) returns that same static pool
   forever. Every message send claims one via `claim_messaging_one_time_prekey` (marks
   `consumed_at`). Once all 24 published rows are consumed, the frontend re-upserts the same
   IDs with `ignoreDuplicates: true` → zero new rows → available count is 0 permanently.
2. **Device-count-scaled readiness targets.** QuantumSecurityDashboardPage and
   KeyManagementPage compute `signed target = active devices` and `one-time target =
   devices × 8`. Stale device rows from reinstalls make those targets unattainable
   ("1/3 signed prekeys"). security-score.ts already fixed this with per-device floors
   (SIGNED_PREKEY_MIN=1, ONE_TIME_PREKEY_MIN=16) but the two pages were not aligned.
3. **Replenish threshold below readiness floor + runs once per session.** Bootstrap tops up
   only when available < 8 (floor is 16) and only once per app session
   (`deviceBootstrappedUsers` cache), so depletion while running is never healed.

## Plan
- [x] Rust: `keys_replenish_one_time_prekeys(user_id, needed)` async command — generates
      FRESH one-time prekeys, appends to active pool (cap 96), retires oldest into legacy
      pool (cap 192, still decrypt-capable), persists encrypted key material, audits.
      Registered in lib.rs. Pool-cap logic extracted + unit-tested.
- [x] security-score.ts: exported ONE_TIME_PREKEY_TARGET (24) beside the floors.
- [x] messaging-bootstrap.ts: rewrote ensureOneTimePrekeys — diffs local pool against ALL
      published rows (incl. consumed), uploads unpublished, replenishes remaining deficit
      with fresh keys; threshold aligned to ONE_TIME_PREKEY_MIN (16), tops up to 24. Added
      30-day prune of consumed rows NOT in the local pool (never republishes a consumed
      key). Exported throttled (60s) + deduped ensurePrekeyReadiness.
- [x] use-dashboard-data.ts: fires ensurePrekeyReadiness when inventory is below floors;
      resulting prekey inserts arrive as realtime events and refresh counts.
- [x] QuantumSecurityDashboardPage.tsx + KeyManagementPage.tsx: per-device floor targets
      (no more device-count-scaled 1/3 and 0/24).
- [x] Verify: cargo test 47+2 passed; vitest 17 passed; tsc clean; vite build clean.

## Validation strategy
- cargo check + cargo test in qguard-messaging/src-tauri.
- npm run build (tsc + vite) in qguard-messaging.
- Manual trace: consumed-out pool → bootstrap → fresh prekeys inserted → counts recover.

## Rollback plan
- All changes additive: new command + frontend logic. Revert the two page target lines and
  ensureOneTimePrekeys body to restore prior behavior; no schema changes.

---

# Archive: Q-Shrink Vault Engine (complete)

Done: core engine, vault wiring, dashboard panel, 30-check round-trip test, tsc/vite clean,
adversarial review, magic-collision fix. Future ideas: multi-file dedup UI, WASM Zstd/Brotli,
bucketed padding, QSHRN2 64-bit sections.

---

# Report Accuracy Round 7 (complete — 2026-07-11)

User audit of sample executive report (PDF/HTML) found mismatches; all fixed + verified:
- Improvement column mixed units (+65 / -75% / -38) -> uniform points with % annotation (Pdf/Docx/Ppt).
- Domain risk targets (x0.30) vs programme target (x0.25) -> shared reduction engine + new
  "Target Reconciliation Verified" validation check (now 7 checks).
- Remediation dates (now+3/6/9wk) -> roadmap wave finish dates.
- Risk forecast 36-month glide (51/32/14) contradicted 26-week plan -> schedule-anchored
  scenarios (Expected / 2x-slippage / No-programme baseline).
- HNDL Exposure (raw 54) vs HNDL Risk (calibrated domain 50) disambiguated + terminology entry.
- Advisor complexity Low vs asset profile High reconciled (max of platform + per-asset rule).
- Fabricated "Archived data repositories" driver removed; "Assets Assessed" KPI -> "Inventoried Assets";
  resource-loading hours off-by-one (989 vs 988) fixed; finding counts (24/27/160) labeled;
  85 target tied to CERTIFICATION_READINESS_THRESHOLD and explained in executive summary.
Verified: tsc clean, vite build clean, report-export-smoke 14 formats green, live report-check 7/7 PASS.

---

# Report Accuracy Round 8 - Scale & Pipeline Audit (complete - 2026-07-11)

google.pdf review (different user) confirmed R7 fixes live; new fixes:
- Wave costs now reconcile to the dollar (renormalised ratios + remainder push; validation check added).
- Budget canonicalised to whole labour-hours (normalizeBudgetUsd) - one budget figure everywhere.
- Finding families now catch "Deprecated SSL/TLS Version"/TLSv1/TLSv1.1, No Hybrid/PQC, OIDs -
  "Other Cryptographic Findings" no longer the #1 executive risk.
- Backend exact COUNT queries: tenant-wide inventory counts truthful past row caps (1500/2500...).
- Parallel-workstream timeline model: 13k-component estate plans 171wk x 64 lanes, not 10,969wk;
  small estates numerically identical. Mirrored in scoped recompute; estimates.parallelWorkstreams added.
- Scope truth: totalAssetCount = true inventory count + "top N by risk" disclosure; inline default
  scope replaced by buildReportScope (single source).
- scanner.ts loadScannerTables explicit limits (was silent PostgREST 1000-row default).
- Smoke suite: new XL_SCALE scenario (4,800 assets / 12,000 components) with scale assertions.
Verified: tsc, vite build, smoke 4 scenarios x 7 formats, live report-check 7/7 PASS.

## Android Version of QGuard Messaging (Tauri 2 Android) — 2026-07-11

Goal: production-ready Android app from qguard-messaging/src-tauri sharing the desktop PQC core
(ML-KEM-768/1024 + X25519 hybrid, ML-DSA-65 + Ed25519 hybrid, AES-256-GCM, HKDF-SHA3-256),
with a premium Material-3-style mobile UI per test_images/android-design_*.png.

### Rust / Android platform
- [x] Cargo.toml: gate keyring/updater/process to desktop; add jni + ndk-context on Android
- [x] security/keystore.rs: platform DEK storage — desktop OS keychain, Android Keystore (hardware-backed AES-GCM via JNI)
- [x] state.rs: route device-storage-key through keystore abstraction (desktop format unchanged)
- [x] lib.rs: mobile data dir via app_data_dir(), cfg(desktop) plugin registration
- [x] capabilities: split desktop-only permissions (updater/process) from cross-platform set
- [x] tauri.conf.json: Android minSdkVersion 29 (Android 10+)
- [x] tauri android init → gen/android Gradle project (Android Studio compatible)
- [x] AndroidManifest: CAMERA / RECORD_AUDIO / MODIFY_AUDIO_SETTINGS / POST_NOTIFICATIONS; MainActivity runtime permission requests
- [x] Android icons via tauri icon; splash/status-bar theme (light, purple accents)
- [x] Release signing: upload keystore + keystore.properties + gradle signingConfig

### Mobile UI (premium light theme, purple gradients, floating cards)
- [x] globals.css: responsive (drop 960px min-width on phones), safe-area insets, mobile overrides
- [x] use-mobile.ts hook + MobileShell (gradient header + floating bottom nav: Home/Chats/Vault/Security/Settings, unread badge)
- [x] Mobile splash + 3-slide onboarding (pre-login, matches design language)
- [x] LoginPage mobile polish (rounded card, gradient CTA)
- [x] SecureChatPage: single-pane mobile flow (list ⇄ thread, back button, details hidden)
- [x] UpdateBanner/app-update: no-op on Android (no updater plugin on mobile)

### Verification
- [x] tsc + vite build clean (tsc exit 0; vite built in 38s)
- [x] cargo test (host) — keystore refactor regressions (0 failed) + 17 frontend vitest pass
- [x] Debug APK built + verified: app-arm64-debug.apk 155MB, contains lib/arm64-v8a/libqguard_messaging_lib.so, pkg com.qguard.messaging v1.2.20, minSdk29/target36, all perms
- [~] Release-signed APK: building (release .so LTO compile in progress) via gradlew assembleArm64Release
- [x] Docs: ANDROID.md + docs/{ANDROID_NATIVE_ARCHITECTURE,BUILD_NATIVE,ANDROID_SECURITY}.md
- Windows blocker solved: tauri symlinks .so into jniLibs (needs Dev Mode); no-admin fix = build .so, copy to jniLibs, gradlew assembleArm64Debug -x rustBuildArm64Debug

## Remove QR Digital Twin → Replace with Harvest Now + validate QR module — 2026-07-15

Guide: Qguard_Wiki/Remove_Digital-Twin_Enhance_Readiness&Assessment
Scope decision: only the Quantum Readiness Digital Twin is removed. PQAuth's Identity
Digital Twin is a separate module mandated by CLAUDE.md (PQAuth section) and stays.

### Removal (QR Digital Twin — frontend-only feature, no dedicated backend)
- [x] Delete src/app/dashboard/quantum-readiness/digital-twin/ (page.tsx)
- [x] App.tsx: remove QuantumReadinessDigitalTwinPage import + route; old URL now `Navigate`-redirects to /dashboard/harvest-now (bookmark continuity)
- [x] _shared.tsx QR_PAGES: Digital Twin tab → "Harvest Now" → /dashboard/harvest-now
- [x] DashboardLayout: Digital Twin item removed; "HNDL Assessment" renamed "Harvest Now (HNDL)" and moved into the old Digital Twin slot
- [x] quantum-readiness/page.tsx MODULES card: Digital Twin → Harvest Now (HNDL), icon EyeOff
- [x] MigrationPlanner "Simulate Outcome" → "Harvest Now Risk" → /dashboard/harvest-now (STAGE_ICONS.simulate/FlaskConical kept — that's the 9-stage workflow)
- [x] Marketing /quantum-readiness-assessment ModuleSpotlight: Digital Twin → Harvest Now spotlight (image /HarvestNow.png); section subtitle updated

### Validation
- [x] grep: zero QR digital-twin references left (6 remaining hits are all PQAuth Identity Digital Twin — intentionally kept)
- [x] tsc --noEmit exit 0; vite build ✓ (45s; only pre-existing chunk-size warnings)
- [x] Live server: /api/v1/quantum-readiness + /api/v1/harvest-now → 401 unauth; 403 SUBSCRIPTION_REQUIRED for Starter (cybersniper26); 200 with real data for Basic (threathunter369)
- [x] SSE: /api/v1/harvest-now/stream → 200 text/event-stream, first hndl-intelligence event has real scan data (hasData:true); ?token= correctly rejected (header-auth by design)
- [x] tools/hndl-check.ts: all 16 sections + empty-state (no fabricated values) PASS
- [x] tools/report-check.ts (REPORT_CHECK_EMAIL=threathunter369@gmail.com, Basic): all I1–I5 live checks PASS incl. HNDL in top business risks
- [x] Subscription matrix: /dashboard/quantum-readiness + /dashboard/harvest-now basic-tier (frontend lib/subscription-access.ts + backend subscription-guard.ts API_MIN_TIER)
- [x] QR pages audit: all 8 remaining pages render from useQuantumReadiness/useAdvisorModel (live backend snapshot; no mock data)

## Quantum Trust Certification Engine™ — 2026-07-16

Guide: Qguard_Wiki/Quantum_Trust_Certification_Engine. Samples: public/Reports/Quantum_Trust_Certification{_Dashboard,}.png
Placement: under Quantum Readiness Assessment Engine (sidebar section + QR_PAGES subnav). Access: BASIC/PRO/ELITE.
Reuse: buildSnapshot (quantum-readiness.ts) + buildReportModel certification criteria (ReportEvidence) for eligibility;
ML-DSA-65 (@noble/post-quantum, same lib as Vault) for signing; ReportQr QR helpers; harvest-now auth/SSE patterns.

### Backend
- [x] supabase/quantum-certification-schema.sql — 11 guide tables + signing-keys table, RLS (owner-only + service-role-only for keys/verify-logs), triggers, realtime publication
- [x] src/types/quantum-certification.ts — shared FE/BE contract
- [x] src/api-server/quantum-certification.ts — eligibility rules engine (configurable policy + platform floors so tenants can't self-certify),
      trust score /1000 + Bronze→Diamond levels (hybrid-evidence + assessment-count gated), POST /issue (SHA3-256 canonical hash + ML-DSA-65 signature + QR URL),
      renew/suspend/revoke/reinstate, continuous monitoring (auto-suspend on drift, lazy expiry, throttled validation writes), downloads log,
      GET /stream SSE (header-auth), audit-package endpoint, PUBLIC verify router (rate-limited 30/min, service-role, live SHA3+ML-DSA verify, verification logs, company search)
- [x] Mount routers in index.ts (public verify BEFORE subscription gateway); subscription-guard: /api/v1/quantum-certification = basic

### Frontend
- [x] lib/subscription-access.ts: /dashboard/quantum-certification = basic
- [x] src/hooks/use-quantum-certification.ts — fetch + SSE + realtime + lifecycle actions
- [x] src/components/certification/QuantumTrustCertificate.tsx — self-contained SVG cert art (faithful to sample; render-verified via sharp)
- [x] src/services/certification/certificate-export.ts — SVG→PNG→PDF (pdf-lib, +metadata page) + JSON + audit package
- [x] src/app/dashboard/quantum-certification/page.tsx — premium dashboard (KPIs, eligibility checklist, cert preview+issue form, trend, level distro, AI advisor, history table, activity, notifications, verification+downloads)
- [x] src/pages/VerifyCertificate.tsx — public portal /verify-certificate(/:id) (ID + company lookup, live integrity/signature)
- [x] App.tsx routes (dashboard + 2 public); DashboardLayout QR section + QR_PAGES subnav + QR hub MODULES card

### Verification
- [x] tools/certification-check.ts — offline: eligibility gating invariant, snapshot criteria, trust-score/level engine, SHA3-256 determinism, ML-DSA-65 sign/verify + tamper detection — ALL PASS
- [x] tsc --noEmit clean; vite build clean (49s)
- [x] Live probes: Starter→403, Basic→200 dashboard (hasData:true, eligibility 3/10 correctly NOT eligible from real evidence), issue→503 SCHEMA_NOT_APPLIED (correctly refused), SSE→200 event-stream, public verify→200 lookup + graceful 404
- [x] docs/QUANTUM_TRUST_CERTIFICATION.md (architecture, DB, API, workflow, lifecycle, security, guides)
- [ ] PENDING USER ACTION: run supabase/quantum-certification-schema.sql in Supabase SQL Editor to enable issuance/signing/public verification; optionally set CERT_VERIFICATION_ORIGIN=https://verify.qguardhelix.com

### Schema collision fix (2026-07-16) — user hit `column "organization" does not exist` at line 57
- [x] Root cause: platform ALREADY has a `certificates` table (X.509/TLS INVENTORY, cols not_before/not_after). My `CREATE TABLE IF NOT EXISTS certificates` no-op'd → index on organization hit the wrong table. Also my expired-cert query used `valid_to` (nonexistent) instead of `not_after` (silent-0 bug).
- [x] DB probe confirmed: only `certificates` exists (4 rows); all my certificate_* child tables + qtc_certificates absent.
- [x] Renamed issued-cert table `certificates` → `quantum_trust_certificates` (schema + indexes + RLS DO-blocks + realtime + trigger). Child tables keep certificate_* prefix (confirmed free).
- [x] Engine: CERT_TABLE='quantum_trust_certificates' const for all issued-cert ops; INVENTORY_CERT_TABLE='certificates' read-only for expired-cert criterion with corrected `not_after` column; removed dead probe line.
- [x] Frontend hook realtime subscribes to quantum_trust_certificates.
- [x] Re-verified: tsc clean, vite build clean, certification-check all pass. (Live re-probe blocked by a transient Supabase network timeout; pre-rename live flow already passed.)
- [x] Schema is idempotent/safe to re-run. User must re-run the corrected supabase/quantum-certification-schema.sql.
