# Live Migration — Massive-Scale Orchestration

Implements `Qguard_Wiki/Live_Migration_Massive_ScalabilityCapable`: enhances
Live Migration Operations to orchestrate real-time PQC migration across
thousands of assets with enterprise fault-tolerance, back-pressure, and
real-time telemetry — additive to the existing page (nothing redesigned).

## Architecture: the orchestrator is the scheduling brain, agents are the workers

The distributed model already exists in the platform and is now coordinated by
a real scheduling engine:

- **Workers** = the Agent Collectors / Patchers. They are stateless, claim work,
  execute the guarded PQC upgrade (snapshot → patch → validate → rollback), and
  report telemetry. Adding workers = horizontal scaling.
- **Durable queue** = Postgres `migration_jobs` (survives process/worker
  restarts — queue persistence).
- **Orchestrator** = `src/api-server/migration-orchestrator.ts`
  (`/api/v1/migration-orchestrator`, Pro+). Schedules, leases, retries,
  recovers and measures — persisting scheduling state in
  `migration_jobs.metadata.orchestration` (no schema migration; works
  immediately).

## Scheduling primitives (real, verified)

Stored per job in `metadata.orchestration`, applied by a **bounded** (≤60
jobs/cycle) reconciliation loop that runs on every snapshot build:

| Primitive | Implementation |
| --- | --- |
| Parallel execution | Many workers claim leasable jobs concurrently |
| Priority queues | Criticality-weighted priority; highest scheduled first |
| Dependency-aware scheduling | Jobs stay `blocked` until `dependsOn` complete |
| Rate limiting / back-pressure | `maxConcurrentPerTenant` caps in-flight leases → no queue backlog / resource starvation |
| Distributed locking (leases) | `assignedAgentId` + lease TTL; idempotent claim prevents double-execution |
| Node-failure recovery | Expired leases (dead worker) are reclaimed → re-queued |
| Exponential-backoff retry | `base × 2^retryCount`, up to `maxRetries` |
| Dead-letter isolation | Exhausted jobs quarantined — a failed asset never blocks others (partial-failure isolation) |
| Checkpointing / idempotency | Reconciliation is idempotent; metadata records lease/retry/checkpoint state |

Pure, offline-testable functions: `toOrchJob`, `jobPhase`,
`planReconciliation`, `computeMetrics`.

## Real-time monitoring (SSE, all real data)

`GET /` + `GET /stream` (15s tick) surface metrics computed from real
`migration_jobs` / `migration_validation_logs` / `scanner_agents` /
`connector_accounts`:

- Job phases: blocked / queued / leased / running / validating / completed /
  retrying / failed / rolled-back / dead-letter / paused.
- Progress: assets upgraded / remaining, overall %, validation %.
- Performance: **throughput (assets/min, 15-min window)**, avg duration, queue
  depth, in-flight vs concurrency cap, **worker utilization**, active workers.
- Reliability: reclaimed leases, retries scheduled, dead-lettered this cycle.
- Fleet health: agents online/degraded/offline, connector health.
- **Data honesty**: customer infra metrics (CPU / memory / network latency) are
  reported **only when an agent actually sends them** in its heartbeat; else
  `null` / "—" — never fabricated. Throughput/duration are `null` until real
  completions exist.

Scale tier (1–10 … 100,000+) is derived from the real job/asset count.

## UI (additive)

`_orchestration.tsx` → `<OrchestrationPanel>` added to the Live Migration page
below the enhancement band: overall-progress bar, live throughput sparkline,
10-phase job breakdown, 6 performance tiles, priority-queue list (priority /
phase / lease / retry / blocked-by), fleet health + per-agent leases, the 10
scheduling/fault-tolerance capabilities, and a reconciliation-activity feed.
Own hook + header-auth SSE.

## Multi-tenancy & security (unchanged, enforced)

Tenant-isolated (caller's RLS client), RBAC (Pro+ tier gate, Starter → 403),
audited via the existing migration events + snapshot audit, integrity-verified
snapshots (see `MIGRATION_SNAPSHOTS.md`), approval workflow (Migration Planner).

## Honest distributed-deployment posture

Correct and performant at any tenant size on a single node today; the
scheduler is written **stateless-worker-ready** (all durable state in
Postgres), so scaling out = running more API instances + more agents. The
remaining true-HA items (multi-node coordination beyond Postgres advisory
semantics, external event bus) are the same roadmap items documented in
`ARCHITECTURE_SCALABILITY_REVIEW.md` — the queue, leases and idempotent claim
are the foundation that makes that migration mechanical.

## Verification (2026-07-17)

- `tsc --noEmit` clean; `vite build` clean.
- `tools/orchestrator-check.ts` — 24/24: phase derivation, dependency blocking,
  lease reclaim (node-failure recovery), backoff retry + dead-letter isolation,
  back-pressure cap, priority ordering, and real metric math (progress, avg
  duration, throughput, validation, agent/connector health, null infra).
- Live (owner): tier gating (Starter 403 / Pro 200), 10 capabilities, honest
  null infra metrics, SSE emitting `orchestrator-update` frames.
